// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Quinn transport adapter for the HTTP/3 server.
//!
//! `h3-quinn` intentionally hides the raw Quinn send half after accepting an
//! incoming bidirectional stream. The server needs Quinn's passive
//! `SendStream::stopped()` notification so a peer `STOP_SENDING` can cancel DNS
//! execution immediately instead of being discovered only when a response is
//! eventually written. This adapter mirrors the h3-quinn 0.0.10 transport
//! traits while retaining one stopped future for each accepted request stream.

use std::convert::TryInto;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{self, Poll};

use bytes::{Buf, Bytes};
use crossbeam_queue::SegQueue;
use futures::{Stream, StreamExt, ready, stream};
use h3::error::Code;
use h3::quic::{self, ConnectionErrorIncoming, StreamErrorIncoming, StreamId, WriteBuf};
use tokio_util::sync::ReusableBoxFuture;

pub(super) type H3PeerStoppedResult = Result<quinn::VarInt, quinn::StoppedError>;

pub(super) type H3PeerStoppedFuture =
    Pin<Box<dyn Future<Output = H3PeerStoppedResult> + Send + Sync + 'static>>;

async fn peer_stop_only<F>(stopped: F) -> H3PeerStoppedResult
where
    F: Future<Output = Result<Option<quinn::VarInt>, quinn::StoppedError>>,
{
    match stopped.await {
        Ok(Some(code)) => Ok(code),
        // `None` means our send side finished normally and the peer
        // acknowledged all bytes. STOP_SENDING can no longer arrive for this
        // stream, so keep the cancellation branch permanently inert.
        Ok(None) => std::future::pending::<H3PeerStoppedResult>().await,
        Err(error) => Err(error),
    }
}

#[derive(Clone, Default)]
pub(super) struct H3PeerStopQueue {
    inner: Arc<SegQueue<H3PeerStoppedFuture>>,
}

impl H3PeerStopQueue {
    #[inline]
    fn push(&self, stopped: H3PeerStoppedFuture) {
        self.inner.push(stopped);
    }

    #[inline]
    pub(super) fn pop_front(&self) -> Option<H3PeerStoppedFuture> {
        self.inner.pop()
    }
}

type BoxStreamSync<'a, T> = Pin<Box<dyn Stream<Item = T> + Sync + Send + 'a>>;

/// h3-quinn-compatible connection which intercepts only incoming bidi streams.
pub(super) struct ServerQuinnConnection {
    inner: h3_quinn::Connection,
    incoming_bi: BoxStreamSync<'static, <quinn::AcceptBi<'static> as Future>::Output>,
    peer_stops: H3PeerStopQueue,
}

impl ServerQuinnConnection {
    pub(super) fn new(conn: quinn::Connection, peer_stops: H3PeerStopQueue) -> Self {
        Self {
            inner: h3_quinn::Connection::new(conn.clone()),
            incoming_bi: Box::pin(stream::unfold(conn, |conn| async {
                Some((conn.accept_bi().await, conn))
            })),
            peer_stops,
        }
    }
}

impl<B> quic::Connection<B> for ServerQuinnConnection
where
    B: Buf,
{
    type OpenStreams = ServerOpenStreams;
    type RecvStream = ServerRecvStream;

    fn poll_accept_bidi(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        let (send, recv) = ready!(self.incoming_bi.poll_next_unpin(cx))
            .expect("incoming HTTP/3 bidi stream never returns None")
            .map_err(convert_connection_error)?;

        let future: H3PeerStoppedFuture = Box::pin(peer_stop_only(send.stopped()));
        self.peer_stops.push(future);

        Poll::Ready(Ok(ServerBidiStream::Direct {
            send: DirectSendStream::new(send),
            recv: DirectRecvStream::new(recv),
        }))
    }

    fn poll_accept_recv(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        <h3_quinn::Connection as quic::Connection<B>>::poll_accept_recv(&mut self.inner, cx)
            .map_ok(ServerRecvStream::Delegated)
    }

    fn opener(&self) -> Self::OpenStreams {
        ServerOpenStreams {
            inner: <h3_quinn::Connection as quic::Connection<B>>::opener(&self.inner),
        }
    }
}

impl<B> quic::OpenStreams<B> for ServerQuinnConnection
where
    B: Buf,
{
    type BidiStream = ServerBidiStream<B>;
    type SendStream = ServerSendStream<B>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        <h3_quinn::Connection as quic::OpenStreams<B>>::poll_open_bidi(&mut self.inner, cx)
            .map_ok(ServerBidiStream::Delegated)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        <h3_quinn::Connection as quic::OpenStreams<B>>::poll_open_send(&mut self.inner, cx)
            .map_ok(ServerSendStream::Delegated)
    }

    fn close(&mut self, code: Code, reason: &[u8]) {
        <h3_quinn::Connection as quic::OpenStreams<B>>::close(&mut self.inner, code, reason);
    }
}

pub(super) struct ServerOpenStreams {
    inner: h3_quinn::OpenStreams,
}

impl Clone for ServerOpenStreams {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<B> quic::OpenStreams<B> for ServerOpenStreams
where
    B: Buf,
{
    type BidiStream = ServerBidiStream<B>;
    type SendStream = ServerSendStream<B>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        <h3_quinn::OpenStreams as quic::OpenStreams<B>>::poll_open_bidi(&mut self.inner, cx)
            .map_ok(ServerBidiStream::Delegated)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        <h3_quinn::OpenStreams as quic::OpenStreams<B>>::poll_open_send(&mut self.inner, cx)
            .map_ok(ServerSendStream::Delegated)
    }

    fn close(&mut self, code: Code, reason: &[u8]) {
        <h3_quinn::OpenStreams as quic::OpenStreams<B>>::close(&mut self.inner, code, reason);
    }
}

pub(super) enum ServerBidiStream<B>
where
    B: Buf,
{
    Direct {
        send: DirectSendStream<B>,
        recv: DirectRecvStream,
    },
    Delegated(h3_quinn::BidiStream<B>),
}

impl<B> quic::BidiStream<B> for ServerBidiStream<B>
where
    B: Buf,
{
    type RecvStream = ServerRecvStream;
    type SendStream = ServerSendStream<B>;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        match self {
            Self::Direct { send, recv } => (
                ServerSendStream::Direct(send),
                ServerRecvStream::Direct(recv),
            ),
            Self::Delegated(stream) => {
                let (send, recv) = quic::BidiStream::split(stream);
                (
                    ServerSendStream::Delegated(send),
                    ServerRecvStream::Delegated(recv),
                )
            }
        }
    }
}

impl<B> quic::RecvStream for ServerBidiStream<B>
where
    B: Buf,
{
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        match self {
            Self::Direct { recv, .. } => quic::RecvStream::poll_data(recv, cx),
            Self::Delegated(stream) => quic::RecvStream::poll_data(stream, cx),
        }
    }

    fn stop_sending(&mut self, error_code: u64) {
        match self {
            Self::Direct { recv, .. } => quic::RecvStream::stop_sending(recv, error_code),
            Self::Delegated(stream) => quic::RecvStream::stop_sending(stream, error_code),
        }
    }

    fn recv_id(&self) -> StreamId {
        match self {
            Self::Direct { recv, .. } => quic::RecvStream::recv_id(recv),
            Self::Delegated(stream) => quic::RecvStream::recv_id(stream),
        }
    }
}

impl<B> quic::SendStream<B> for ServerBidiStream<B>
where
    B: Buf,
{
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        match self {
            Self::Direct { send, .. } => quic::SendStream::poll_ready(send, cx),
            Self::Delegated(stream) => quic::SendStream::poll_ready(stream, cx),
        }
    }

    fn send_data<T: Into<WriteBuf<B>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        match self {
            Self::Direct { send, .. } => quic::SendStream::send_data(send, data),
            Self::Delegated(stream) => quic::SendStream::send_data(stream, data),
        }
    }

    fn poll_finish(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        match self {
            Self::Direct { send, .. } => quic::SendStream::poll_finish(send, cx),
            Self::Delegated(stream) => quic::SendStream::poll_finish(stream, cx),
        }
    }

    fn reset(&mut self, reset_code: u64) {
        match self {
            Self::Direct { send, .. } => quic::SendStream::reset(send, reset_code),
            Self::Delegated(stream) => quic::SendStream::reset(stream, reset_code),
        }
    }

    fn send_id(&self) -> StreamId {
        match self {
            Self::Direct { send, .. } => quic::SendStream::send_id(send),
            Self::Delegated(stream) => quic::SendStream::send_id(stream),
        }
    }
}

impl<B> quic::SendStreamUnframed<B> for ServerBidiStream<B>
where
    B: Buf,
{
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut task::Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        match self {
            Self::Direct { send, .. } => quic::SendStreamUnframed::poll_send(send, cx, buf),
            Self::Delegated(stream) => quic::SendStreamUnframed::poll_send(stream, cx, buf),
        }
    }
}

pub(super) enum ServerSendStream<B>
where
    B: Buf,
{
    Direct(DirectSendStream<B>),
    Delegated(h3_quinn::SendStream<B>),
}

impl<B> quic::SendStream<B> for ServerSendStream<B>
where
    B: Buf,
{
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        match self {
            Self::Direct(stream) => quic::SendStream::poll_ready(stream, cx),
            Self::Delegated(stream) => quic::SendStream::poll_ready(stream, cx),
        }
    }

    fn send_data<T: Into<WriteBuf<B>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        match self {
            Self::Direct(stream) => quic::SendStream::send_data(stream, data),
            Self::Delegated(stream) => quic::SendStream::send_data(stream, data),
        }
    }

    fn poll_finish(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        match self {
            Self::Direct(stream) => quic::SendStream::poll_finish(stream, cx),
            Self::Delegated(stream) => quic::SendStream::poll_finish(stream, cx),
        }
    }

    fn reset(&mut self, reset_code: u64) {
        match self {
            Self::Direct(stream) => quic::SendStream::reset(stream, reset_code),
            Self::Delegated(stream) => quic::SendStream::reset(stream, reset_code),
        }
    }

    fn send_id(&self) -> StreamId {
        match self {
            Self::Direct(stream) => quic::SendStream::send_id(stream),
            Self::Delegated(stream) => quic::SendStream::send_id(stream),
        }
    }
}

impl<B> quic::SendStreamUnframed<B> for ServerSendStream<B>
where
    B: Buf,
{
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut task::Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        match self {
            Self::Direct(stream) => quic::SendStreamUnframed::poll_send(stream, cx, buf),
            Self::Delegated(stream) => quic::SendStreamUnframed::poll_send(stream, cx, buf),
        }
    }
}

pub(super) enum ServerRecvStream {
    Direct(DirectRecvStream),
    Delegated(h3_quinn::RecvStream),
}

impl quic::RecvStream for ServerRecvStream {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        match self {
            Self::Direct(stream) => quic::RecvStream::poll_data(stream, cx),
            Self::Delegated(stream) => quic::RecvStream::poll_data(stream, cx),
        }
    }

    fn stop_sending(&mut self, error_code: u64) {
        match self {
            Self::Direct(stream) => quic::RecvStream::stop_sending(stream, error_code),
            Self::Delegated(stream) => quic::RecvStream::stop_sending(stream, error_code),
        }
    }

    fn recv_id(&self) -> StreamId {
        match self {
            Self::Direct(stream) => quic::RecvStream::recv_id(stream),
            Self::Delegated(stream) => quic::RecvStream::recv_id(stream),
        }
    }
}

pub(super) struct DirectRecvStream {
    stream: Option<quinn::RecvStream>,
    read_chunk_fut: ReusableBoxFuture<
        'static,
        (
            quinn::RecvStream,
            Result<Option<quinn::Chunk>, quinn::ReadError>,
        ),
    >,
}

impl DirectRecvStream {
    fn new(stream: quinn::RecvStream) -> Self {
        Self {
            stream: Some(stream),
            read_chunk_fut: ReusableBoxFuture::new(async { unreachable!() }),
        }
    }
}

impl quic::RecvStream for DirectRecvStream {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        if let Some(mut stream) = self.stream.take() {
            self.read_chunk_fut.set(async move {
                let chunk = stream.read_chunk(usize::MAX, true).await;
                (stream, chunk)
            });
        }

        let (stream, chunk) = ready!(self.read_chunk_fut.poll(cx));
        self.stream = Some(stream);
        Poll::Ready(Ok(chunk
            .map_err(convert_read_error_to_stream_error)?
            .map(|chunk| chunk.bytes)))
    }

    fn stop_sending(&mut self, error_code: u64) {
        if let Some(stream) = self.stream.as_mut() {
            let _ = stream.stop(quinn::VarInt::from_u64(error_code).expect("invalid error code"));
        }
    }

    fn recv_id(&self) -> StreamId {
        let id: u64 = self
            .stream
            .as_ref()
            .expect("receive stream must be present outside poll_data")
            .id()
            .into();
        id.try_into().expect("invalid stream id")
    }
}

pub(super) struct DirectSendStream<B>
where
    B: Buf,
{
    stream: quinn::SendStream,
    writing: Option<WriteBuf<B>>,
}

impl<B> DirectSendStream<B>
where
    B: Buf,
{
    fn new(stream: quinn::SendStream) -> Self {
        Self {
            stream,
            writing: None,
        }
    }
}

impl<B> quic::SendStream<B> for DirectSendStream<B>
where
    B: Buf,
{
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        if let Some(data) = self.writing.as_mut() {
            while data.has_remaining() {
                let written = ready!(Pin::new(&mut self.stream).poll_write(cx, data.chunk()))
                    .map_err(convert_write_error_to_stream_error)?;
                data.advance(written);
            }
        }
        self.writing = None;
        Poll::Ready(Ok(()))
    }

    fn send_data<T: Into<WriteBuf<B>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        if self.writing.is_some() {
            return Err(StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: ConnectionErrorIncoming::InternalError(
                    "send_data called while HTTP/3 send stream is not ready".to_string(),
                ),
            });
        }
        self.writing = Some(data.into());
        Ok(())
    }

    fn poll_finish(
        &mut self,
        _cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), StreamErrorIncoming>> {
        Poll::Ready(
            self.stream
                .finish()
                .map_err(|error| StreamErrorIncoming::Unknown(Box::new(error))),
        )
    }

    fn reset(&mut self, reset_code: u64) {
        let _ = self
            .stream
            .reset(quinn::VarInt::from_u64(reset_code).unwrap_or(quinn::VarInt::MAX));
    }

    fn send_id(&self) -> StreamId {
        let id: u64 = self.stream.id().into();
        id.try_into().expect("invalid stream id")
    }
}

impl<B> quic::SendStreamUnframed<B> for DirectSendStream<B>
where
    B: Buf,
{
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut task::Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        if self.writing.is_some() {
            panic!("poll_send called while HTTP/3 send stream is not ready");
        }
        let written = ready!(Pin::new(&mut self.stream).poll_write(cx, buf.chunk()))
            .map_err(convert_write_error_to_stream_error)?;
        buf.advance(written);
        Poll::Ready(Ok(written))
    }
}

fn convert_connection_error(error: quinn::ConnectionError) -> ConnectionErrorIncoming {
    match error {
        quinn::ConnectionError::ApplicationClosed(application_close) => {
            ConnectionErrorIncoming::ApplicationClose {
                error_code: application_close.error_code.into(),
            }
        }
        quinn::ConnectionError::TimedOut => ConnectionErrorIncoming::Timeout,
        error @ quinn::ConnectionError::VersionMismatch
        | error @ quinn::ConnectionError::Reset
        | error @ quinn::ConnectionError::LocallyClosed
        | error @ quinn::ConnectionError::CidsExhausted
        | error @ quinn::ConnectionError::TransportError(_)
        | error @ quinn::ConnectionError::ConnectionClosed(_) => {
            ConnectionErrorIncoming::Undefined(Arc::new(error))
        }
    }
}

fn convert_read_error_to_stream_error(error: quinn::ReadError) -> StreamErrorIncoming {
    match error {
        quinn::ReadError::Reset(code) => StreamErrorIncoming::StreamTerminated {
            error_code: code.into_inner(),
        },
        quinn::ReadError::ConnectionLost(error) => StreamErrorIncoming::ConnectionErrorIncoming {
            connection_error: convert_connection_error(error),
        },
        error @ quinn::ReadError::ClosedStream => StreamErrorIncoming::Unknown(Box::new(error)),
        quinn::ReadError::IllegalOrderedRead => {
            panic!("HTTP/3 adapter only performs ordered reads")
        }
        error @ quinn::ReadError::ZeroRttRejected => StreamErrorIncoming::Unknown(Box::new(error)),
    }
}

fn convert_write_error_to_stream_error(error: quinn::WriteError) -> StreamErrorIncoming {
    match error {
        quinn::WriteError::Stopped(code) => StreamErrorIncoming::StreamTerminated {
            error_code: code.into_inner(),
        },
        quinn::WriteError::ConnectionLost(error) => StreamErrorIncoming::ConnectionErrorIncoming {
            connection_error: convert_connection_error(error),
        },
        error @ quinn::WriteError::ClosedStream | error @ quinn::WriteError::ZeroRttRejected => {
            StreamErrorIncoming::Unknown(Box::new(error))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn peer_stop_filter_reports_only_actual_stop_sending() {
        let code = quinn::VarInt::from_u32(0x10C);
        let stopped = peer_stop_only(async move { Ok::<_, quinn::StoppedError>(Some(code)) })
            .await
            .expect("STOP_SENDING should be reported");

        assert_eq!(stopped, code);
    }

    #[tokio::test]
    async fn peer_stop_queue_preserves_accept_order_without_locking() {
        let queue = H3PeerStopQueue::default();

        queue.push(Box::pin(async { Ok(quinn::VarInt::from_u32(0x10C)) }));
        queue.push(Box::pin(async { Ok(quinn::VarInt::from_u32(0x10D)) }));

        assert_eq!(
            queue
                .pop_front()
                .expect("first watcher should exist")
                .await
                .expect("first watcher should resolve"),
            quinn::VarInt::from_u32(0x10C)
        );
        assert_eq!(
            queue
                .pop_front()
                .expect("second watcher should exist")
                .await
                .expect("second watcher should resolve"),
            quinn::VarInt::from_u32(0x10D)
        );
        assert!(queue.pop_front().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn normal_send_completion_is_not_peer_cancellation() {
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            peer_stop_only(async { Ok::<_, quinn::StoppedError>(None) }),
        )
        .await;

        assert!(
            result.is_err(),
            "a normally acknowledged local FIN must not cancel request execution"
        );
    }
}
