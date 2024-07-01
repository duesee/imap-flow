#![forbid(unsafe_code)]

pub mod client;
mod client_send;
pub mod fragmentizer;
mod handle;
mod receive;
pub mod server;
mod server_send;
#[cfg(feature = "stream")]
pub mod stream;
#[cfg(test)]
mod tests;
pub mod types;

// Test examples from imap-next's README.
#[doc = include_str!("../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;

/// State machine with sans I/O pattern.
///
/// This trait is the interface between types that implement IMAP protocol flows and I/O drivers.
/// Most notably [`Client`](client::Client) and [`Server`](server::Server) both implement
/// this trait whereas [`Stream`](stream::Stream) uses the trait for implementing the I/O drivers.
pub trait State {
    /// Event emitted while progressing the state.
    type Event;

    /// Error emitted while progressing the state.
    type Error;

    /// Enqueue input bytes.
    ///
    /// These bytes may be used during the next [`Self::next`] call.
    fn enqueue_input(&mut self, bytes: &[u8]);

    /// Progress the state until the next event (or interrupt).
    fn next(&mut self) -> Result<Self::Event, Interrupt<Self::Error>>;
}

impl<F: State> State for &mut F {
    type Event = F::Event;
    type Error = F::Error;

    fn enqueue_input(&mut self, bytes: &[u8]) {
        (*self).enqueue_input(bytes);
    }

    fn next(&mut self) -> Result<Self::Event, Interrupt<Self::Error>> {
        (*self).next()
    }
}

/// State progression was interrupted by an event that needs to be handled externally.
#[must_use = "If state progression is interrupted the interrupt must be handled. Ignoring this might result in a deadlock on IMAP level"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Interrupt<E> {
    /// An IO operation is necessary. Ignoring this might result in a deadlock on IMAP level.
    Io(Io),
    /// An error occurred. Ignoring this might result in an undefined IMAP state.
    Error(E),
}

/// User of `imap-next` must perform an IO operation to progress the state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Io {
    /// More bytes must be read and passed to [`State::enqueue_input`].
    NeedMoreInput,
    /// Given bytes must be written.
    Output(Vec<u8>),
}
