//! This is the simplest possible client using rustls-postquantum, based on
//! `simpleclient.rs`.
//!
//! It sends a HTTP request to pq.cloudflareresearch.com and prints the response to
//! stdout.  Observe in that output: `kex=X25519MLKEM768`
//!
//! Note that `unwrap()` is used to deal with networking errors; this is not something
//! that is sensible outside of example code.

use std::io::{Read, Write, stdout};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::Connection;

fn main() {
    env_logger::init();

    let provider = Arc::new(rustls_post_quantum::provider());

    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    let config = rustls::ClientConfig::builder(provider)
        .with_root_certificates(root_store)
        .with_no_client_auth()
        .unwrap();

    let config = Arc::new(config);
    let mut conn = config
        .connect("pq.cloudflareresearch.com".try_into().unwrap())
        .build()
        .unwrap();
    let mut sock = TcpStream::connect("pq.cloudflareresearch.com:443").unwrap();

    while conn.is_handshaking() || conn.wants_write() {
        conn.write_tls(&mut sock).unwrap();
        conn.read_tls(&mut sock).unwrap();
        conn.process_new_packets().unwrap();
    }

    let ciphersuite = conn.negotiated_cipher_suite().unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    )
    .unwrap();
    let kx_group = conn.negotiated_key_exchange_group().unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current key exchange group: {kx_group:?}",
    )
    .unwrap();

    conn.writer()
        .write_all(
            concat!(
                "GET /cdn-cgi/trace HTTP/1.0\r\n",
                "Host: pq.cloudflareresearch.com\r\n",
                "Connection: close\r\n",
                "Accept-Encoding: identity\r\n",
                "\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
    conn.write_tls(&mut sock).unwrap();

    let mut plaintext = Vec::new();
    loop {
        match conn.read_tls(&mut sock) {
            Ok(0) => break,
            Ok(_) => {
                conn.process_new_packets().unwrap();
                let mut buf = [0u8; 4096];
                loop {
                    let result: std::io::Result<usize> = conn.reader().read(&mut buf);
                    match result {
                        Ok(0) => break,
                        Ok(n) => plaintext.extend_from_slice(&buf[..n]),
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => panic!("read error: {e}"),
                    }
                }
            }
            Err(e) => panic!("read_tls error: {e}"),
        }
    }
    stdout().write_all(&plaintext).unwrap();
}
