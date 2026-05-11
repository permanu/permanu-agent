use std::{env, io, os::unix::net::UnixDatagram, time::Duration};

use tokio::sync::watch;
use tracing::{debug, warn};

pub fn notify_ready() {
    if let Err(err) = notify_state("READY=1") {
        warn!(error = ?err, "systemd READY notification failed");
    }
}

pub fn spawn_watchdog(mut shutdown: watch::Receiver<bool>) -> Option<tokio::task::JoinHandle<()>> {
    let interval = watchdog_interval_from_env()?;
    Some(tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        return;
                    }
                }
                _ = tokio::time::sleep(interval) => {
                    if let Err(err) = notify_state("WATCHDOG=1") {
                        debug!(error = ?err, "systemd watchdog notification failed");
                    }
                }
            }
        }
    }))
}

fn watchdog_interval_from_env() -> Option<Duration> {
    env::var("WATCHDOG_USEC")
        .ok()
        .and_then(|value| watchdog_interval_from_usec(&value))
}

fn watchdog_interval_from_usec(value: &str) -> Option<Duration> {
    let usec = value.parse::<u64>().ok().filter(|value| *value > 0)?;
    let half = (usec / 2).max(1);
    Some(Duration::from_micros(half))
}

fn notify_state(state: &str) -> io::Result<()> {
    let Some(socket) = env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    let socket = socket
        .into_string()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NOTIFY_SOCKET is not UTF-8"))?;
    let datagram = UnixDatagram::unbound()?;
    connect_notify_socket(&datagram, &socket)?;
    datagram.send(state.as_bytes())?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn connect_notify_socket(datagram: &UnixDatagram, socket: &str) -> io::Result<()> {
    if let Some(name) = socket.strip_prefix('@') {
        use std::{os::linux::net::SocketAddrExt, os::unix::net::SocketAddr};

        let addr = SocketAddr::from_abstract_name(name.as_bytes())?;
        return datagram.connect_addr(&addr);
    }
    datagram.connect(socket)
}

#[cfg(not(target_os = "linux"))]
fn connect_notify_socket(datagram: &UnixDatagram, socket: &str) -> io::Result<()> {
    if socket.starts_with('@') {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "abstract NOTIFY_SOCKET requires Linux",
        ));
    }
    datagram.connect(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watchdog_interval_uses_half_of_systemd_deadline() {
        assert_eq!(
            watchdog_interval_from_usec("30000000"),
            Some(Duration::from_secs(15))
        );
    }

    #[test]
    fn watchdog_interval_rejects_invalid_values() {
        assert_eq!(watchdog_interval_from_usec(""), None);
        assert_eq!(watchdog_interval_from_usec("abc"), None);
        assert_eq!(watchdog_interval_from_usec("0"), None);
    }
}
