//! Loopback dashboard listener and optional browser launch.
use std::{io, net::SocketAddr};
use tokio::net::TcpListener;

pub async fn bind(host: &str, port: u16, strict: bool) -> io::Result<TcpListener> {
    let host = host.trim_matches(['[', ']']);
    let last = if strict || port == 0 {
        port
    } else {
        port.saturating_add(10)
    };
    for candidate in port..=last {
        match TcpListener::bind((host, candidate)).await {
            Ok(listener) => return Ok(listener),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse && candidate < last => continue,
            Err(error) => return Err(error),
        }
    }
    unreachable!("inclusive port range always contains at least one port")
}

pub fn url(address: SocketAddr) -> String {
    format!("http://{address}/")
}

pub fn open_browser(url: &str) -> io::Result<()> {
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut c = std::process::Command::new("rundll32");
        c.args(["url.dll,FileProtocolHandler", url]);
        c
    };
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    };
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let mut command = {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    command.spawn().map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn fallback_strict_and_ephemeral_ports() {
        let occupied = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = occupied.local_addr().unwrap().port();
        let err = bind("127.0.0.1", port, true).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
        if port < u16::MAX {
            let fallback = bind("127.0.0.1", port, false).await.unwrap();
            assert!(fallback.local_addr().unwrap().port() > port);
        }
        let ephemeral = bind("127.0.0.1", 0, true).await.unwrap();
        assert_ne!(ephemeral.local_addr().unwrap().port(), 0);
    }
    #[test]
    fn ipv6_url_is_bracketed() {
        assert_eq!(url("[::1]:1234".parse().unwrap()), "http://[::1]:1234/");
    }
}
