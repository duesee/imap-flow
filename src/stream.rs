use std::{num::NonZeroUsize, pin::Pin};

use bytes::{Buf, BytesMut};
#[cfg(debug_assertions)]
use imap_types::utils::escape_byte_string;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(debug_assertions)]
use tracing::trace;

// TODO: Reconsider this. Do we really need Stream + AnyStream? What is the smallest API that we need to expose?

pub trait Stream: AsyncRead + AsyncWrite + Send {}

impl<S: AsyncRead + AsyncWrite + Send> Stream for S {}

pub struct AnyStream(pub Pin<Box<dyn Stream>>);

impl AnyStream {
    pub fn new<S: Stream + 'static>(stream: S) -> Self {
        Self(Box::pin(stream))
    }

    /// Reads at least one byte into the buffer and returns the number of read bytes.
    ///
    /// Returns [`StreamError::Closed`] when no bytes could be read.
    pub async fn read(&mut self, read_buffer: &mut ReadBuffer) -> Result<NonZeroUsize, ReadError> {
        let current_len = read_buffer.bytes.len();

        let byte_count = match read_buffer.limit {
            None => self.0.read_buf(&mut read_buffer.bytes).await?,
            Some(limit) => {
                let remaining_byte_count = limit.saturating_sub(current_len);
                if remaining_byte_count == 0 {
                    return Err(ReadError::ReadBufferOverflow);
                }

                (&mut self.0)
                    .take(remaining_byte_count as u64)
                    .read_buf(&mut read_buffer.bytes)
                    .await?
            }
        };

        #[cfg(debug_assertions)]
        trace!(
            data = escape_byte_string(&read_buffer.bytes[current_len..]),
            "io/read/raw"
        );

        match NonZeroUsize::new(byte_count) {
            None => {
                // The result is 0 if the stream reached "end of file" or the read buffer was
                // already full before calling `read_buf`. Because we use an unlimited buffer we
                // know that the first case occurred.
                Err(ReadError::Closed)
            }
            Some(byte_count) => Ok(byte_count),
        }
    }

    /// Writes all bytes from the write buffer.
    ///
    /// Returns [`StreamError::Closed`] when not all bytes could be written.
    pub async fn write_all(&mut self, write_buffer: &mut WriteBuffer) -> Result<(), WriteError> {
        while !write_buffer.bytes.is_empty() {
            let byte_count = self.0.write(&write_buffer.bytes).await?;
            #[cfg(debug_assertions)]
            trace!(
                data = escape_byte_string(&write_buffer.bytes[..byte_count]),
                "io/write/raw"
            );
            write_buffer.bytes.advance(byte_count);

            if byte_count == 0 {
                // The result is 0 if the stream doesn't accept bytes anymore or the write buffer
                // was already empty before calling `write_buf`. Because we checked the buffer
                // we know that the first case occurred.
                return Err(WriteError::Closed);
            }
        }

        Ok(())
    }
}

/// Error during reading from a [`Stream`].
#[derive(Debug, Error)]
pub enum ReadError {
    /// The operation failed because the stream is closed.
    ///
    /// We detect this by checking if the read byte count is 0. Whether the stream is
    /// closed indefinitely or temporarily depend on the actual stream implementation.
    #[error("Stream was closed")]
    Closed,
    /// An I/O error occurred in the underlying stream.
    #[error(transparent)]
    Io(#[from] tokio::io::Error),
    #[error("Read buffer has overflown")]
    ReadBufferOverflow,
}

/// Error during writing to a [`Stream`].
#[derive(Debug, Error)]
pub enum WriteError {
    /// The operation failed because the stream is closed.
    ///
    /// We detect this by checking if the written byte count is 0. Whether the stream is
    /// closed indefinitely or temporarily depend on the actual stream implementation.
    #[error("Stream was closed")]
    Closed,
    /// An I/O error occurred in the underlying stream.
    #[error(transparent)]
    Io(#[from] tokio::io::Error),
}

#[derive(Debug, Error)]
#[error("Stream was closed")]
pub struct ClosedError;

pub struct ReadBuffer {
    pub bytes: BytesMut,
    pub limit: Option<usize>,
}

pub struct WriteBuffer {
    pub bytes: BytesMut,
}
