use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncWrite};

trait AsyncReadWrite: AsyncRead + AsyncWrite + Send {
    fn read(self: Pin<&Self>) -> Pin<&(dyn AsyncRead + Send)>;
    fn read_mut(self: Pin<&mut Self>) -> Pin<&mut (dyn AsyncRead + Send)>;
    fn write(self: Pin<&Self>) -> Pin<&(dyn AsyncWrite + Send)>;
    fn write_mut(self: Pin<&mut Self>) -> Pin<&mut (dyn AsyncWrite + Send)>;
}

impl<S: AsyncRead + AsyncWrite + Send> AsyncReadWrite for S {
    fn read(self: Pin<&Self>) -> Pin<&(dyn AsyncRead + Send)> {
        self
    }
    fn read_mut(self: Pin<&mut Self>) -> Pin<&mut (dyn AsyncRead + Send)> {
        self
    }
    fn write(self: Pin<&Self>) -> Pin<&(dyn AsyncWrite + Send)> {
        self
    }
    fn write_mut(self: Pin<&mut Self>) -> Pin<&mut (dyn AsyncWrite + Send)> {
        self
    }
}

pub struct Stream {
    underlying: Pin<Box<dyn AsyncReadWrite>>,
}

impl Stream {
    pub fn new<S>(stream: S) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        Self {
            underlying: Box::pin(stream),
        }
    }

    pub fn read(&self) -> Pin<&(dyn AsyncRead + Send)> {
        self.underlying.as_ref().read()
    }
    pub fn read_mut(&mut self) -> Pin<&mut (dyn AsyncRead + Send)> {
        self.underlying.as_mut().read_mut()
    }
    pub fn write(&self) -> Pin<&(dyn AsyncWrite + Send)> {
        self.underlying.as_ref().write()
    }
    pub fn write_mut(&mut self) -> Pin<&mut (dyn AsyncWrite + Send)> {
        self.underlying.as_mut().write_mut()
    }
}
