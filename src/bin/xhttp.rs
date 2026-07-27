use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::{timeout, Duration};

use tokio_rustls::rustls::{self, Certificate, PrivateKey};
use tokio_rustls::TlsAcceptor;

/// Tipo de erro unificado para o projeto
type XhttpError = Box<dyn std::error::Error + Send + Sync>;

/// Sessão xHTTP ativa com canais para comunicação GET<->POST<->SSH
#[allow(dead_code)]
struct XhttpSession {
    post_tx: mpsc::Sender<Vec<u8>>,
    get_tx: mpsc::Sender<Vec<u8>>,
    active: Arc<RwLock<bool>>,
}

static SESSIONS: once_cell::sync::Lazy<Arc<Mutex<HashMap<String, XhttpSession>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

// Cache do ServerConfig TLS (evita reparse de certificados)
static TLS_SERVER_CONFIG_CACHE: once_cell::sync::Lazy<Arc<Mutex<Option<Arc<rustls::ServerConfig>>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(Mutex::new(None)));

#[tokio::main]
async fn main() -> Result<(), XhttpError> {
    let port = get_port();
    let status = get_status();
    let ssh_port = get_ssh_port();

    println!("[Mpro] xHTTP v3.6.0 (Latency Optimized + Low Latency Networks)");
    println!("[xHTTP] Porta: {} | SSH Backend: 127.0.0.1:{}", port, ssh_port);

    // Pré-carrega TLS config para conexões instantâneas
    preload_tls_config();

    let listener = TcpListener::bind(format!("[::]:{}", port)).await.map_err(|e| Box::new(e) as XhttpError)?;
    let status_arc = Arc::new(status);

    loop {
        match listener.accept().await {
            Ok((client_stream, _addr)) => {
                // TCP_NODELAY para eliminar latência do Nagle algorithm
                let _ = client_stream.set_nodelay(true);
                // TCP_QUICKACK para redes com alta latência (ACK imediato, sem delay)
                #[cfg(target_os = "linux")]
                {
                    use std::os::fd::AsRawFd;
                    let fd = client_stream.as_raw_fd();
                    unsafe {
                        // TCP_QUICKACK = 12, setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &val, sizeof(val))
                        let val: libc::c_int = 1;
                        libc::setsockopt(fd, libc::IPPROTO_TCP, 12, &val as *const _ as *const libc::c_void, std::mem::size_of_val(&val) as libc::socklen_t);
                    }
                }

                let status = status_arc.clone();
                tokio::spawn(async move {
                    let _ = handle_xhttp_client(client_stream, &status, ssh_port).await;
                });
            }
            Err(e) => {
                println!("[xHTTP] Erro aceitar conexao: {}", e);
            }
        }
    }
}

/// Pré-carrega a configuração TLS para evitar delay na primeira conexão
fn preload_tls_config() {
    let cert_path = "/opt/mpro/cert.pem";
    let key_path = "/opt/mpro/key.pem";
    if let Ok(config) = build_tls_config(cert_path, key_path) {
        let _ = TLS_SERVER_CONFIG_CACHE.try_lock().map(|mut cache| {
            *cache = Some(Arc::new(config));
        });
    }
}

async fn handle_xhttp_client(
    stream: TcpStream,
    status: &str,
    ssh_port: u16,
) -> Result<(), XhttpError> {
    // OTIMIZADO: Peek de 200ms — ultra rápido para detectar tipo de conexão
    let mut peek_buf = [0u8; 4];
    let peek_result = timeout(Duration::from_millis(200), stream.peek(&mut peek_buf)).await;
    let bytes_peeked = match peek_result {
        Ok(Ok(n)) => n,
        _ => 0,
    };

    if bytes_peeked == 0 {
        return handle_ssh_direct(stream, ssh_port).await;
    }
    
    let first_byte = peek_buf[0];

    // Detecta TLS (0x16 = TLS ClientHello)
    if first_byte == 0x16 {
        return handle_tls_dual(stream, status, ssh_port).await;
    }

    // Detecta se parece ser HTTP (GET, POST, etc)
    if first_byte >= 0x41 && first_byte <= 0x5A {
        return handle_http_dual_raw(stream, status, ssh_port).await;
    }

    // Fallback para SSH direto
    handle_ssh_direct(stream, ssh_port).await
}

async fn handle_tls_dual(
    stream: TcpStream,
    status: &str,
    ssh_port: u16,
) -> Result<(), XhttpError> {
    // Usa TLS config em cache (evita reparse de certificados)
    let acceptor = get_cached_acceptor()?;

    let mut tls_stream = acceptor.accept(stream).await.map_err(|e| Box::new(e) as XhttpError)?;

    let mut buf = vec![0u8; 16384];
    // OTIMIZADO: 1.5s timeout para HTTP read (reduzido de 2s)
    let n = match timeout(Duration::from_millis(1500), tls_stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => {
            return handle_ssh_direct_tls(tls_stream, ssh_port, None).await;
        }
    };

    let data = &buf[..n];
    let http_str = String::from_utf8_lossy(data);
    
    // Detecta xHTTP/SocksRevive paths
    if http_str.contains("x-session-id") 
        || http_str.contains("/ssh/") 
        || http_str.contains("/xhttp/") 
        || http_str.contains("/split/")
        || http_str.contains("/revive/")
        || http_str.contains("X-Session")
    {
        if let Some((method, path)) = parse_http_request(&http_str) {
            match method.as_str() {
                "GET" => return handle_xhttp_get_tls(&mut tls_stream, &path, status, ssh_port).await,
                "POST" => return handle_xhttp_post_tls(&mut tls_stream, data, &path, status).await,
                _ => {}
            }
        }
    }

    if http_str.contains("HTTP/1.") {
        let resp = format!("HTTP/1.1 101 ({})\r\n\r\nHTTP/1.1 200 ({})\r\n\r\n", status, status);
        tls_stream.write_all(resp.as_bytes()).await.map_err(|e| Box::new(e) as XhttpError)?;
        return handle_ssh_direct_tls(tls_stream, ssh_port, None).await;
    }

    handle_ssh_direct_tls(tls_stream, ssh_port, Some(data.to_vec())).await
}

async fn handle_http_dual_raw(mut stream: TcpStream, status: &str, ssh_port: u16) -> Result<(), XhttpError> {
    let mut buf = vec![0u8; 16384];
    let n = stream.read(&mut buf).await.map_err(|e| Box::new(e) as XhttpError)?;
    let http_str = String::from_utf8_lossy(&buf[..n]);
    
    if http_str.contains("x-session-id") 
        || http_str.contains("/ssh/") 
        || http_str.contains("/xhttp/") 
        || http_str.contains("/split/")
        || http_str.contains("/revive/")
        || http_str.contains("X-Session")
    {
        if let Some((method, path)) = parse_http_request(&http_str) {
            match method.as_str() {
                "GET" => return handle_xhttp_get_raw(&mut stream, &path, status, ssh_port).await,
                "POST" => return handle_xhttp_post_raw(&mut stream, &buf[..n], &path, status).await,
                _ => {}
            }
        }
    }

    if http_str.contains("HTTP/1.") {
        let resp = format!("HTTP/1.1 101 ({})\r\n\r\nHTTP/1.1 200 ({})\r\n\r\n", status, status);
        stream.write_all(resp.as_bytes()).await.map_err(|e| Box::new(e) as XhttpError)?;
    }
    
    let ssh = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await.map_err(|e| Box::new(e) as XhttpError)?;
    let _ = ssh.set_nodelay(true);
    let (mut r, mut w) = stream.into_split();
    let (mut sr, mut sw) = ssh.into_split();
    let _ = tokio::join!(tokio::io::copy(&mut r, &mut sw), tokio::io::copy(&mut sr, &mut w));
    Ok(())
}

async fn handle_ssh_direct(stream: TcpStream, ssh_port: u16) -> Result<(), XhttpError> {
    let ssh = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await.map_err(|e| Box::new(e) as XhttpError)?;
    let _ = ssh.set_nodelay(true);
    let (mut r, mut w) = stream.into_split();
    let (mut sr, mut sw) = ssh.into_split();
    let _ = tokio::join!(tokio::io::copy(&mut r, &mut sw), tokio::io::copy(&mut sr, &mut w));
    Ok(())
}

async fn handle_ssh_direct_tls(tls_stream: tokio_rustls::server::TlsStream<TcpStream>, ssh_port: u16, initial_data: Option<Vec<u8>>) -> Result<(), XhttpError> {
    let mut ssh = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await.map_err(|e| Box::new(e) as XhttpError)?;
    let _ = ssh.set_nodelay(true);
    if let Some(data) = initial_data {
        ssh.write_all(&data).await.map_err(|e| Box::new(e) as XhttpError)?;
    }
    let (mut r, mut w) = tokio::io::split(tls_stream);
    let (mut sr, mut sw) = ssh.into_split();
    let _ = tokio::join!(tokio::io::copy(&mut r, &mut sw), tokio::io::copy(&mut sr, &mut w));
    Ok(())
}

// --- XHTTP Acceleration Logic (Ultra Fast + Low Latency Optimized) ---

async fn handle_xhttp_get_tls(tls: &mut tokio_rustls::server::TlsStream<TcpStream>, path: &str, status: &str, ssh_port: u16) -> Result<(), XhttpError> {
    let (sid, _) = extract_path_info(path);
    
    // Limpa sessão antiga ANTES de criar nova — evita conflitos de reconexão
    {
        let mut sessions = SESSIONS.lock().await;
        if let Some(old) = sessions.get(&sid) {
            *old.active.write().await = false;
        }
        sessions.remove(&sid);
    }

    // *** OTIMIZAÇÃO ULTRA: Resposta 200 IMEDIATA antes de conectar SSH ***
    // Isso elimina o travamento "Conectando" — o cliente recebe 200 instantaneamente
    // Connection: keep-alive permite reusar a mesma conexão TCP para POSTs seguintes
    let resp = format!(
        "HTTP/1.1 200 OK\r\n\
        Content-Type: application/octet-stream\r\n\
        Transfer-Encoding: chunked\r\n\
        Connection: keep-alive\r\n\
        Keep-Alive: timeout=30, max=100\r\n\
        Cache-Control: no-store, no-cache, must-revalidate, max-age=0\r\n\
        Pragma: no-cache\r\n\
        Expires: 0\r\n\
        X-Session-ID: {}\r\n\
        X-Status: {}\r\n\
        X-Socksrevive: active\r\n\r\n", 
        sid, status
    );
    tls.write_all(resp.as_bytes()).await.map_err(|e| Box::new(e) as XhttpError)?;
    tls.flush().await.map_err(|e| Box::new(e) as XhttpError)?;

    // Conecta SSH em paralelo (já não bloqueia o cliente — resposta 200 já foi enviada)
    let ssh = timeout(Duration::from_secs(3), TcpStream::connect(format!("127.0.0.1:{}", ssh_port)))
        .await
        .map_err(|_| Box::new(std::io::Error::new(std::io::ErrorKind::TimedOut, "SSH Connect Timeout")) as XhttpError)?
        .map_err(|e| Box::new(e) as XhttpError)?;
    let _ = ssh.set_nodelay(true);
    let (mut sr, mut sw) = ssh.into_split();

    // Canal grande (16384) para reduzir backpressure em redes com alta latência
    let (ptx, mut prx) = mpsc::channel::<Vec<u8>>(16384);
    let (gtx, mut grx) = mpsc::channel::<Vec<u8>>(16384);
    let act = Arc::new(RwLock::new(true));
    
    SESSIONS.lock().await.insert(sid.clone(), XhttpSession { 
        post_tx: ptx, 
        get_tx: gtx.clone(), 
        active: act.clone() 
    });
    
    // Task: Encaminha dados POST -> SSH (write)
    let act_c = act.clone();
    tokio::spawn(async move { 
        while let Some(d) = prx.recv().await { 
            if !*act_c.read().await { break; }
            if sw.write_all(&d).await.is_err() { break; }
        }
        let mut a = act_c.write().await;
        *a = false;
    });

    // Task: Lê dados do SSH -> Canal GET (read)
    let gtx_c = gtx.clone();
    let act_c2 = act.clone();
    tokio::spawn(async move { 
        let mut b = vec![0u8; 65536]; 
        while let Ok(Ok(n)) = timeout(Duration::from_secs(600), sr.read(&mut b)).await { 
            if n == 0 || gtx_c.send(b[..n].to_vec()).await.is_err() { break; } 
            if !*act_c2.read().await { break; }
        }
        let mut a = act_c2.write().await;
        *a = false;
    });

    // Stream GET: envia chunks do SSH para o cliente TLS
    while let Some(d) = grx.recv().await {
        if !*act.read().await { break; }
        if tls.write_all(format!("{:x}\r\n", d.len()).as_bytes()).await.is_err() { break; }
        if tls.write_all(&d).await.is_err() { break; }
        if tls.write_all(b"\r\n").await.is_err() { break; }
        let _ = tls.flush().await;
    }
    
    // Cleanup
    let mut a = act.write().await;
    *a = false;
    SESSIONS.lock().await.remove(&sid);
    Ok(())
}

async fn handle_xhttp_get_raw(stream: &mut TcpStream, path: &str, status: &str, ssh_port: u16) -> Result<(), XhttpError> {
    let (sid, _) = extract_path_info(path);
    
    // Limpa sessão antiga
    {
        let mut sessions = SESSIONS.lock().await;
        if let Some(old) = sessions.get(&sid) {
            *old.active.write().await = false;
        }
        sessions.remove(&sid);
    }

    // *** OTIMIZAÇÃO ULTRA: Resposta 200 IMEDIATA antes de conectar SSH ***
    let resp = format!(
        "HTTP/1.1 200 OK\r\n\
        Content-Type: application/octet-stream\r\n\
        Transfer-Encoding: chunked\r\n\
        Connection: keep-alive\r\n\
        Keep-Alive: timeout=30, max=100\r\n\
        Cache-Control: no-store, no-cache, must-revalidate, max-age=0\r\n\
        Pragma: no-cache\r\n\
        Expires: 0\r\n\
        X-Session-ID: {}\r\n\
        X-Status: {}\r\n\
        X-Socksrevive: active\r\n\r\n", 
        sid, status
    );
    stream.write_all(resp.as_bytes()).await.map_err(|e| Box::new(e) as XhttpError)?;
    stream.flush().await.map_err(|e| Box::new(e) as XhttpError)?;

    // Conecta SSH em paralelo
    let ssh = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await.map_err(|e| Box::new(e) as XhttpError)?;
    let _ = ssh.set_nodelay(true);
    let (mut sr, mut sw) = ssh.into_split();

    let (ptx, mut prx) = mpsc::channel::<Vec<u8>>(16384);
    let (gtx, mut grx) = mpsc::channel::<Vec<u8>>(16384);
    let act = Arc::new(RwLock::new(true));

    SESSIONS.lock().await.insert(sid.clone(), XhttpSession { 
        post_tx: ptx, 
        get_tx: gtx.clone(), 
        active: act.clone() 
    });
    
    // Task: Encaminha dados POST -> SSH (write)
    let act_c = act.clone();
    tokio::spawn(async move { 
        while let Some(d) = prx.recv().await { 
            if !*act_c.read().await { break; }
            if sw.write_all(&d).await.is_err() { break; }
        } 
        let mut a = act_c.write().await;
        *a = false;
    });

    // Task: Lê dados do SSH -> Canal GET (read)
    let gtx_c = gtx.clone();
    let act_c2 = act.clone();
    tokio::spawn(async move { 
        let mut b = vec![0u8; 65536]; 
        while let Ok(Ok(n)) = timeout(Duration::from_secs(600), sr.read(&mut b)).await { 
            if n == 0 || gtx_c.send(b[..n].to_vec()).await.is_err() { break; } 
            if !*act_c2.read().await { break; }
        }
        let mut a = act_c2.write().await;
        *a = false;
    });

    // Stream GET
    while let Some(d) = grx.recv().await {
        if !*act.read().await { break; }
        if stream.write_all(format!("{:x}\r\n", d.len()).as_bytes()).await.is_err() { break; }
        if stream.write_all(&d).await.is_err() { break; }
        if stream.write_all(b"\r\n").await.is_err() { break; }
        let _ = stream.flush().await;
    }
    
    let mut a = act.write().await;
    *a = false;
    SESSIONS.lock().await.remove(&sid);
    Ok(())
}

async fn handle_xhttp_post_tls(tls: &mut tokio_rustls::server::TlsStream<TcpStream>, req: &[u8], path: &str, _: &str) -> Result<(), XhttpError> {
    let (sid, _) = extract_path_info(path);
    let cl = extract_content_length_from_bytes(req).unwrap_or(0);
    let h_end = req.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0) + 4;
    let mut body = req[h_end..].to_vec();
    
    // Lê o corpo completo do POST (sem timeout — mais rápido em redes lentas)
    if body.len() < cl {
        let mut b = vec![0u8; cl - body.len()];
        let _ = tls.read_exact(&mut b).await;
        body.extend_from_slice(&b);
    }
    
    if let Some(s) = SESSIONS.lock().await.get(&sid) { 
        let _ = s.post_tx.try_send(body); // try_send evita bloqueio se canal estiver cheio
    }
    
    // Resposta 200 com keep-alive para próxima POST rápida (evita nova conexão TCP)
    let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\nKeep-Alive: timeout=30\r\nX-Socksrevive: ack\r\n\r\n").await;
    let _ = tls.flush().await;
    Ok(())
}

async fn handle_xhttp_post_raw(stream: &mut TcpStream, req: &[u8], path: &str, _: &str) -> Result<(), XhttpError> {
    let (sid, _) = extract_path_info(path);
    let cl = extract_content_length_from_bytes(req).unwrap_or(0);
    let h_end = req.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0) + 4;
    let mut body = req[h_end..].to_vec();
    
    if body.len() < cl {
        let mut b = vec![0u8; cl - body.len()];
        let _ = stream.read_exact(&mut b).await;
        body.extend_from_slice(&b);
    }
    
    if let Some(s) = SESSIONS.lock().await.get(&sid) { 
        let _ = s.post_tx.try_send(body);
    }
    
    // Resposta 200 com keep-alive para reutilizar conexão TCP
    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\nKeep-Alive: timeout=30\r\nX-Socksrevive: ack\r\n\r\n").await;
    let _ = stream.flush().await;
    Ok(())
}

fn parse_http_request(data: &str) -> Option<(String, String)> {
    let line = data.lines().next()?;
    let p: Vec<&str> = line.split_whitespace().collect();
    if p.len() >= 2 { Some((p[0].to_string(), p[1].to_string())) } else { None }
}

fn extract_path_info(path: &str) -> (String, Option<u64>) {
    let p = path.split('?').next().unwrap_or(path).trim_start_matches('/').split('/').collect::<Vec<&str>>();
    if p.is_empty() || p[0].is_empty() { return (String::new(), None); }
    if p.len() >= 2 {
        // Suporte para paths: /ssh/{id}, /xhttp/{id}, /split/{id}, /revive/{id}
        if ["ssh", "xhttp", "split", "revive"].contains(&p[0]) {
            return (p[1].to_string(), if p.len() >= 3 { p[2].parse().ok() } else { None });
        }
        // Se só tem 1 segmento, usa como session ID
        return (p[0].to_string(), p[1].parse().ok());
    }
    (p[0].to_string(), None)
}

fn extract_content_length_from_bytes(data: &[u8]) -> Option<usize> {
    let s = String::from_utf8_lossy(data);
    for l in s.lines() { 
        if l.to_lowercase().starts_with("content-length:") { 
            return l.split(':').nth(1)?.trim().parse().ok(); 
        } 
    }
    None
}

fn build_tls_config(cp: &str, kp: &str) -> Result<rustls::ServerConfig, XhttpError> {
    let certs: Vec<Certificate> = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(cp).map_err(|e| Box::new(e) as XhttpError)?)).map_err(|e| Box::new(e) as XhttpError)?.into_iter().map(Certificate).collect();
    let keys: Vec<PrivateKey> = rustls_pemfile::pkcs8_private_keys(&mut std::io::BufReader::new(std::fs::File::open(kp).map_err(|e| Box::new(e) as XhttpError)?)).map_err(|e| Box::new(e) as XhttpError)?.into_iter().map(PrivateKey).collect();
    if certs.is_empty() || keys.is_empty() { return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Certs empty")) as XhttpError); }
    let mut c = rustls::ServerConfig::builder().with_safe_defaults().with_no_client_auth().with_single_cert(certs, keys.into_iter().next().unwrap()).map_err(|e| Box::new(e) as XhttpError)?;
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(c)
}

fn get_cached_acceptor() -> Result<TlsAcceptor, XhttpError> {
    // Tenta pegar do cache primeiro (evita reparse de certs a cada conexão)
    if let Ok(cache) = TLS_SERVER_CONFIG_CACHE.try_lock() {
        if let Some(config) = cache.as_ref() {
            return Ok(TlsAcceptor::from(Arc::clone(config)));
        }
    }
    
    // Fallback: carrega do disco
    let cert_path = "/opt/mpro/cert.pem";
    let key_path = "/opt/mpro/key.pem";
    let config = build_tls_config(cert_path, key_path)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn get_port() -> u16 { std::env::args().enumerate().find(|(_, a)| a == "--port" || a == "-p").and_then(|(i, _)| std::env::args().nth(i+1)).and_then(|a| a.parse().ok()).unwrap_or(443) }
fn get_ssh_port() -> u16 { std::env::args().enumerate().find(|(_, a)| a == "--ssh-port").and_then(|(i, _)| std::env::args().nth(i+1)).and_then(|a| a.parse().ok()).unwrap_or(22) }
fn get_status() -> String { std::env::args().enumerate().find(|(_, a)| a == "--status" || a == "-s").and_then(|(i, _)| std::env::args().nth(i+1)).unwrap_or("@Mpro".to_string()) }
