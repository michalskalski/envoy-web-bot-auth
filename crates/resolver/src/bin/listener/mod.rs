//! Transport binding, graceful shutdown, and health probing.

use axum::Router;
use clap::Args;
use std::{
    net::SocketAddr,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::{Path, PathBuf},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Args)]
pub(super) struct ProbeArgs {
    #[arg(long)]
    pub(super) socket: PathBuf,
    #[arg(long, default_value_t = 250)]
    pub(super) timeout_ms: u64,
}

#[derive(Debug)]
pub(super) enum ListenAddress {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

impl ListenAddress {
    pub(super) fn parse(value: &str) -> Result<Self, &'static str> {
        if let Some(address) = value.strip_prefix("tcp://") {
            let address = address
                .parse::<SocketAddr>()
                .map_err(|_| "invalid_tcp_listen")?;
            return Ok(Self::Tcp(address));
        }
        if let Some(path) = value.strip_prefix("unix://") {
            let path = PathBuf::from(path);
            if !path.is_absolute() || path.as_os_str().len() > 100 {
                return Err("invalid_unix_listen");
            }
            return Ok(Self::Unix(path));
        }
        Err("invalid_listen_scheme")
    }

    pub(super) const fn kind(&self) -> &'static str {
        match self {
            Self::Tcp(_) => "tcp",
            Self::Unix(_) => "unix",
        }
    }

    pub(super) fn exposed_tcp_address(&self) -> Option<SocketAddr> {
        match self {
            Self::Tcp(address) if !address.ip().is_loopback() => Some(*address),
            Self::Tcp(_) | Self::Unix(_) => None,
        }
    }
}

pub(super) async fn serve_app(listen: ListenAddress, app: Router) -> Result<(), &'static str> {
    match listen {
        ListenAddress::Tcp(address) => {
            let listener = tokio::net::TcpListener::bind(address)
                .await
                .map_err(|_| "listen_bind_failed")?;
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal())
                .await
                .map_err(|_| "serve_failed")?;
        }
        ListenAddress::Unix(path) => serve_unix(path, app).await?,
    }
    Ok(())
}

async fn serve_unix(path: PathBuf, app: Router) -> Result<(), &'static str> {
    prepare_socket_path(&path)?;
    let listener = tokio::net::UnixListener::bind(&path).map_err(|_| "listen_bind_failed")?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))
        .map_err(|_| "socket_permissions_failed")?;
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|_| "serve_failed");
    if let Err(reason) = remove_own_socket(&path) {
        eprintln!("resolver event=shutdown_problem reason={reason}");
    }
    result
}

pub(super) fn prepare_socket_path(path: &Path) -> Result<(), &'static str> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            std::fs::remove_file(path).map_err(|_| "stale_socket_cleanup_failed")
        }
        Ok(_) => Err("socket_path_not_socket"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("socket_path_inspection_failed"),
    }
}

pub(super) fn remove_own_socket(path: &Path) -> Result<(), &'static str> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            std::fs::remove_file(path).map_err(|_| "socket_cleanup_failed")
        }
        Ok(_) => Err("socket_cleanup_target_changed"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("socket_cleanup_inspection_failed"),
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let terminate = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut signal) => {
                    signal.recv().await;
                }
                Err(_) => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate => {},
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

pub(super) async fn probe(args: ProbeArgs) -> Result<(), &'static str> {
    let operation = async {
        let mut stream = tokio::net::UnixStream::connect(&args.socket)
            .await
            .map_err(|_| "probe_connect_failed")?;
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: resolver\r\nConnection: close\r\n\r\n")
            .await
            .map_err(|_| "probe_write_failed")?;
        let mut response = [0u8; 128];
        let read = stream
            .read(&mut response)
            .await
            .map_err(|_| "probe_read_failed")?;
        if !response[..read].starts_with(b"HTTP/1.1 204") {
            return Err("probe_unhealthy");
        }
        Ok(())
    };
    tokio::time::timeout(std::time::Duration::from_millis(args.timeout_ms), operation)
        .await
        .map_err(|_| "probe_timeout")?
}
