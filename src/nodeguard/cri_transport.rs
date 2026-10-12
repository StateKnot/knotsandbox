//! Shutdown closes only the accepted transport FD. The caller must separately
//! retain and drain all admitted mutation/host/journal owners.
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::{
    sync::{CancellationToken, WaitForCancellationFutureOwned},
    task::{TaskTracker, task_tracker::TaskTrackerToken},
};
use tonic::transport::server::Connected;

#[derive(Clone, Default)]
pub struct RuntimeTransport {
    connections: TaskTracker,
    close_io: CancellationToken,
}

impl RuntimeTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn wrap<I: Connected>(&self, io: I) -> io::Result<RuntimeIo<I>> {
        let owner = self.connections.token();
        if self.connections.is_closed() {
            // Even rejection releases the actual FD before its tracking token.
            drop(io);
            return Err(closed());
        }
        let info = io.connect_info();
        Ok(RuntimeIo {
            io: Some(io),
            info,
            closing: Box::pin(self.close_io.clone().cancelled_owned()),
            _owner: owner,
        })
    }

    pub(super) fn stop_accepting(&self) {
        self.connections.close();
    }

    pub(super) fn close_io(&self) {
        self.stop_accepting();
        self.close_io.cancel();
    }

    pub(super) async fn wait_closed(&self) {
        self.connections.wait().await;
    }

    #[cfg(test)]
    pub(super) fn connection_count(&self) -> usize {
        self.connections.len()
    }
}

pub struct RuntimeIo<I: Connected> {
    // Rust drops fields in declaration order. The actual IO is always released
    // before its connection owner, including connection error/unwind paths.
    io: Option<I>,
    info: I::ConnectInfo,
    closing: Pin<Box<WaitForCancellationFutureOwned>>,
    _owner: TaskTrackerToken,
}

fn closed() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "Host runtime transport is draining",
    )
}

impl<I: Connected> Connected for RuntimeIo<I> {
    type ConnectInfo = I::ConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.info.clone()
    }
}

impl<I: Connected> RuntimeIo<I> {
    fn poll_closed(&mut self, cx: &mut Context<'_>) -> bool {
        if self.closing.as_mut().poll(cx).is_ready() {
            // Both read/write register the same cancellation wakeup. Taking
            // and dropping the FD interrupts transport flow-control waits;
            // the token remains until tonic drops this real IO wrapper.
            drop(self.io.take());
        }
        self.io.is_none()
    }
}

impl<I> AsyncRead for RuntimeIo<I>
where
    I: Connected + AsyncRead + Unpin,
    I::ConnectInfo: Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.poll_closed(cx) {
            return Poll::Ready(Err(closed()));
        }
        match this.io.as_mut() {
            Some(io) => Pin::new(io).poll_read(cx, buffer),
            None => Poll::Ready(Err(closed())),
        }
    }
}

impl<I> AsyncWrite for RuntimeIo<I>
where
    I: Connected + AsyncWrite + Unpin,
    I::ConnectInfo: Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.poll_closed(cx) {
            return Poll::Ready(Err(closed()));
        }
        match this.io.as_mut() {
            Some(io) => Pin::new(io).poll_write(cx, buffer),
            None => Poll::Ready(Err(closed())),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.poll_closed(cx) {
            return Poll::Ready(Err(closed()));
        }
        match this.io.as_mut() {
            Some(io) => Pin::new(io).poll_write_vectored(cx, buffers),
            None => Poll::Ready(Err(closed())),
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.io.as_ref().is_some_and(AsyncWrite::is_write_vectored)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.poll_closed(cx) {
            return Poll::Ready(Err(closed()));
        }
        match this.io.as_mut() {
            Some(io) => Pin::new(io).poll_flush(cx),
            None => Poll::Ready(Err(closed())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.poll_closed(cx) {
            return Poll::Ready(Err(closed()));
        }
        match this.io.as_mut() {
            Some(io) => Pin::new(io).poll_shutdown(cx),
            None => Poll::Ready(Err(closed())),
        }
    }
}
