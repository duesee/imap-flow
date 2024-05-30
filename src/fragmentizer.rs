use std::{collections::VecDeque, ops::Range};

use imap_codec::decode::Decoder;
use imap_types::core::{LiteralMode, Tag};

/// Limites the size of messages that can be decoded by [`Fragmentizer`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MaxMessageSize {
    /// Messages of unlimited size are supported.
    ///
    /// Using this might be dangerous because a buffer with the size of the message will be
    /// created. This would allow an attacker to allocate an arbitrary amount of memory.
    Unlimited,
    /// Messages up to the given size limit are supported.
    ///
    /// If the size limit is exceeded then any following bytes of the current message will be
    /// dropped. However, the fragments will still be parsed so that the end of the message can
    /// be detected. Decoding the message with the exceeding size will fail.
    Limited(u32),
}

/// The character sequence used for ending a line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LineEnding {
    /// The line ends with the character `\n`.
    Lf,
    /// The line ends with the character sequence `\r\n`.
    CrLf,
}

/// Used by a line to announce a literal following the line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiteralAnnouncement {
    /// The mode of the announced literal.
    pub mode: LiteralMode,
    /// The length of the announced literal in bytes.
    pub length: u32,
}

/// Describes a fragment found by the [`Fragmentizer::progress`].
///
/// The corresponding bytes can be retrieved via [`Fragmentizer::fragment_bytes`]
/// until the last fragment of the message is reached. After that the next call of
/// [`Fragmentizer::progress`] will start the next message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FragmentInfo {
    /// The fragment is a line.
    Line {
        /// Inclusive start index relative to the current message.
        start: usize,
        /// Exclusive end index relative to the current message.
        end: usize,
        /// Whether the next fragment will be a literal.
        announcement: Option<LiteralAnnouncement>,
        /// The detected ending sequence for this line.
        ending: LineEnding,
    },
    /// The fragment is a literal.
    Literal {
        /// Inclusive start index relative to the current message.
        start: usize,
        /// Exclusive end index relative to the current message.
        end: usize,
    },
}

impl FragmentInfo {
    /// The range relative to the current message.
    pub fn range(self) -> Range<usize> {
        match self {
            FragmentInfo::Line { start, end, .. } => start..end,
            FragmentInfo::Literal { start, end } => start..end,
        }
    }
}

/// An error returned by [`Fragmentizer::decode_message`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeMessageError<'a, C: Decoder> {
    /// The message is malformed.
    DecodingFailure(C::Error<'a>),
    /// Not all bytes of the message were used when decoding the message.
    DecodingRemainder {
        /// The decoded message.
        message: C::Message<'a>,
        /// The unused bytes.
        remainder: &'a [u8],
    },
    /// Max message size was exceeded and bytes were dropped.
    MessageTooLong { initial: &'a [u8] },
}

/// Parser for IMAP message fragments.
///
/// A fragment is either a line or a literal. A single IMAP message may consist of multiple
/// fragments.
///
/// This utility is useful because:
/// - It can reliable detect when all bytes of a message were received. Only then it makes
/// sense to decode the actual message. This allows us to decode large messages efficiently.
/// - Even if the message is malformed it allows us to drop the right number of bytes. This
/// prevents us from treating untrusted bytes (e.g. literal bytes) as IMAP messages.
/// - It has support for max message length. Any exceeding bytes will be dropped. This
/// prevents an attacker from allocating indefinite amount of memory.
/// - It allows us to handle literals before the message is complete. This is important for IMAP
/// servers because they need to accept or reject literals from the client.
#[derive(Clone, Debug)]
pub struct Fragmentizer {
    unparsed_buffer: VecDeque<u8>,
    max_message_size: MaxMessageSize,
    max_message_size_exceeded: bool,
    message_buffer: Vec<u8>,
    parser: Option<Parser>,
}

impl Fragmentizer {
    pub fn new(max_message_size: MaxMessageSize) -> Self {
        Self {
            unparsed_buffer: VecDeque::new(),
            max_message_size,
            max_message_size_exceeded: false,
            message_buffer: Vec::new(),
            parser: Some(Parser::Line(LineParser::new(0))),
        }
    }

    /// Enqueues more byte that can be parsed by [`Fragmentizer::progress`].
    ///
    /// Note that the message size limit is not enforced on the enqueued bytes. You can limit
    /// the size of the enqueued bytes by only calling this function if more bytes are necessary.
    /// More bytes are necessary if [`Fragmentizer::progress`] returns `None`.
    pub fn enqueue_bytes(&mut self, bytes: &[u8]) {
        self.unparsed_buffer.extend(bytes);
    }

    /// Returns whether the size limit is exceeded for the current message.
    pub fn is_max_message_size_exceeded(&self) -> bool {
        self.max_message_size_exceeded
    }

    /// Returns whether the current message was fully parsed.
    pub fn is_message_complete(&self) -> bool {
        self.parser.is_none()
    }

    /// Returns the bytes of the current message.
    ///
    /// Note that the bytes might be incomplete:
    /// - The message might not be fully parsed yet and [`Fragmentizer::progress`] need to be
    ///   called. You can check whether the message is complete via
    ///   [`Fragmentizer::is_message_complete`].
    /// - The size limit might be exceeded and bytes might be dropped. You can check this
    ///   via [`Fragmentizer::is_max_message_size_exceeded`]
    pub fn message_bytes(&self) -> &[u8] {
        &self.message_buffer
    }

    pub fn fragment_bytes(&self, fragment_info: FragmentInfo) -> &[u8] {
        let (start, end) = match fragment_info {
            FragmentInfo::Line { start, end, .. } => (start, end),
            FragmentInfo::Literal { start, end } => (start, end),
        };
        let start = start.min(self.message_buffer.len());
        let end = end.min(self.message_buffer.len());
        &self.message_buffer[start..end]
    }

    /// Skips the current message and starts the next message.
    ///
    /// Warning: This function is dangerous.
    #[allow(unused)]
    pub fn skip_message(&mut self) {
        self.max_message_size_exceeded = false;
        self.message_buffer.clear();
        self.parser = Some(Parser::Line(LineParser::new(0)));
    }

    pub fn progress(&mut self) -> Option<FragmentInfo> {
        let parser = match &mut self.parser {
            Some(parser) => parser,
            None => {
                self.max_message_size_exceeded = false;
                self.message_buffer.clear();
                self.parser.insert(Parser::Line(LineParser::new(0)))
            }
        };

        let (parsed_byte_count, fragment) = parser.parse(&self.unparsed_buffer);
        self.dequeue_parsed_bytes(parsed_byte_count);

        if let Some(fragment) = fragment {
            self.parser = match fragment {
                FragmentInfo::Line {
                    announcement: None, ..
                } => None,
                FragmentInfo::Line {
                    end,
                    announcement: Some(LiteralAnnouncement { length, .. }),
                    ..
                } => Some(Parser::Literal(LiteralParser::new(end, length))),
                FragmentInfo::Literal { end, .. } => Some(Parser::Line(LineParser::new(end))),
            }
        }

        fragment
    }

    pub fn decode_tag(&self) -> Option<Tag> {
        parse_tag(&self.message_buffer)
    }

    pub fn decode_message<'a, C: Decoder>(
        &'a self,
        codec: &C,
    ) -> Result<C::Message<'a>, DecodeMessageError<'a, C>> {
        if self.max_message_size_exceeded {
            return Err(DecodeMessageError::MessageTooLong {
                initial: &self.message_buffer,
            });
        }

        let (remainder, message) = match codec.decode(&self.message_buffer) {
            Ok(res) => res,
            Err(err) => return Err(DecodeMessageError::DecodingFailure(err)),
        };

        if !remainder.is_empty() {
            return Err(DecodeMessageError::DecodingRemainder { message, remainder });
        }

        Ok(message)
    }

    fn dequeue_parsed_bytes(&mut self, parsed_byte_count: usize) {
        let parsed_bytes = self.unparsed_buffer.drain(..parsed_byte_count);
        let remaining_size = match self.max_message_size {
            MaxMessageSize::Unlimited => None,
            MaxMessageSize::Limited(size) => Some(size as usize - self.message_buffer.len()),
        };

        match remaining_size {
            Some(remaining_size) if remaining_size < parsed_byte_count => {
                let remaining_bytes = parsed_bytes.take(remaining_size);
                self.message_buffer.extend(remaining_bytes);
                self.max_message_size_exceeded = true;
            }
            _ => {
                self.message_buffer.extend(parsed_bytes);
            }
        }
    }
}

#[derive(Clone, Debug)]
enum Parser {
    Line(LineParser),
    Literal(LiteralParser),
}

impl Parser {
    fn parse(&mut self, unprocessed_bytes: &VecDeque<u8>) -> (usize, Option<FragmentInfo>) {
        match self {
            Parser::Line(parser) => parser.parse(unprocessed_bytes),
            Parser::Literal(parser) => parser.parse(unprocessed_bytes),
        }
    }
}

#[derive(Clone, Debug)]
struct LineParser {
    start: usize,
    end: usize,
    last_byte: LastByte,
}

impl LineParser {
    fn new(start: usize) -> Self {
        Self {
            start,
            end: start,
            last_byte: LastByte::Other,
        }
    }

    fn parse(&mut self, unprocessed_bytes: &VecDeque<u8>) -> (usize, Option<FragmentInfo>) {
        let mut parsed_byte_count = 0;
        let mut parsed_line = None;

        for &next_byte in unprocessed_bytes {
            parsed_byte_count += 1;
            self.end += 1;

            self.last_byte = match self.last_byte {
                LastByte::Other => match next_byte {
                    b'\r' => LastByte::Cr { announcement: None },
                    b'\n' => {
                        parsed_line = Some(FragmentInfo::Line {
                            start: self.start,
                            end: self.end,
                            announcement: None,
                            ending: LineEnding::Lf,
                        });
                        LastByte::Other
                    }
                    b'{' => LastByte::OpeningBracket,
                    _ => LastByte::Other,
                },
                LastByte::OpeningBracket => match next_byte {
                    b'\r' => LastByte::Cr { announcement: None },
                    b'\n' => {
                        parsed_line = Some(FragmentInfo::Line {
                            start: self.start,
                            end: self.end,
                            announcement: None,
                            ending: LineEnding::Lf,
                        });
                        LastByte::Other
                    }
                    b'{' => LastByte::OpeningBracket,
                    b'0'..=b'9' => {
                        let digit = (next_byte - b'0') as u32;
                        LastByte::Digit { length: digit }
                    }
                    _ => LastByte::Other,
                },
                LastByte::Plus { length } => match next_byte {
                    b'\r' => LastByte::Cr { announcement: None },
                    b'\n' => {
                        parsed_line = Some(FragmentInfo::Line {
                            start: self.start,
                            end: self.end,
                            announcement: None,
                            ending: LineEnding::Lf,
                        });
                        LastByte::Other
                    }
                    b'{' => LastByte::OpeningBracket,
                    b'}' => LastByte::ClosingBracket {
                        announcement: LiteralAnnouncement {
                            mode: LiteralMode::NonSync,
                            length,
                        },
                    },
                    _ => LastByte::Other,
                },
                LastByte::Digit { length } => match next_byte {
                    b'\r' => LastByte::Cr { announcement: None },
                    b'\n' => {
                        parsed_line = Some(FragmentInfo::Line {
                            start: self.start,
                            end: self.end,
                            announcement: None,
                            ending: LineEnding::Lf,
                        });
                        LastByte::Other
                    }
                    b'{' => LastByte::OpeningBracket,
                    b'0'..=b'9' => {
                        let digit = (next_byte - b'0') as u32;
                        let new_length = length.checked_mul(10).and_then(|x| x.checked_add(digit));
                        match new_length {
                            None => LastByte::Other,
                            Some(length) => LastByte::Digit { length },
                        }
                    }
                    b'+' => LastByte::Plus { length },
                    b'}' => LastByte::ClosingBracket {
                        announcement: LiteralAnnouncement {
                            mode: LiteralMode::Sync,
                            length,
                        },
                    },
                    _ => LastByte::Other,
                },
                LastByte::ClosingBracket { announcement } => match next_byte {
                    b'\r' => LastByte::Cr {
                        announcement: Some(announcement),
                    },
                    b'\n' => {
                        parsed_line = Some(FragmentInfo::Line {
                            start: self.start,
                            end: self.end,
                            announcement: Some(announcement),
                            ending: LineEnding::Lf,
                        });
                        LastByte::Other
                    }
                    b'{' => LastByte::OpeningBracket,
                    _ => LastByte::Other,
                },
                LastByte::Cr { announcement } => match next_byte {
                    b'\r' => LastByte::Cr { announcement: None },
                    b'\n' => {
                        parsed_line = Some(FragmentInfo::Line {
                            start: self.start,
                            end: self.end,
                            announcement,
                            ending: LineEnding::CrLf,
                        });
                        LastByte::Other
                    }
                    b'{' => LastByte::OpeningBracket,
                    _ => LastByte::Other,
                },
            };

            if parsed_line.is_some() {
                break;
            }
        }

        (parsed_byte_count, parsed_line)
    }
}

#[derive(Clone, Debug)]
enum LastByte {
    Other,
    OpeningBracket,
    Digit {
        length: u32,
    },
    Plus {
        length: u32,
    },
    ClosingBracket {
        announcement: LiteralAnnouncement,
    },
    Cr {
        announcement: Option<LiteralAnnouncement>,
    },
}

#[derive(Clone, Debug)]
struct LiteralParser {
    start: usize,
    end: usize,
    remaining: u32,
}

impl LiteralParser {
    fn new(start: usize, length: u32) -> Self {
        Self {
            start,
            end: start,
            remaining: length,
        }
    }

    fn parse(&mut self, unprocessed_bytes: &VecDeque<u8>) -> (usize, Option<FragmentInfo>) {
        if unprocessed_bytes.len() < self.remaining as usize {
            let parsed_byte_count = unprocessed_bytes.len();
            self.end += parsed_byte_count;
            self.remaining -= parsed_byte_count as u32;
            (parsed_byte_count, None)
        } else {
            let parsed_byte_count = self.remaining as usize;
            self.end += parsed_byte_count;
            self.remaining = 0;
            let parsed_literal = FragmentInfo::Literal {
                start: self.start,
                end: self.end,
            };
            (parsed_byte_count, Some(parsed_literal))
        }
    }
}

pub fn parse_tag(message_bytes: &[u8]) -> Option<Tag> {
    let mut bytes = message_bytes.iter().enumerate();
    let sp = loop {
        let (i, byte) = bytes.next()?;
        match byte {
            b' ' => {
                // A tag is always delimited by SP
                break i;
            }
            b'\n' => {
                // End of line reached
                return None;
            }
            _ => {
                // Parse more bytes
                continue;
            }
        }
    };

    Tag::try_from(&message_bytes[..sp]).ok()
}

#[cfg(test)]
mod tests {
    use core::panic;
    use std::collections::VecDeque;

    use imap_codec::{decode::ResponseDecodeError, CommandCodec, ResponseCodec};
    use imap_types::{
        command::{Command, CommandBody},
        core::{LiteralMode, Tag},
    };

    use super::{
        parse_tag, FragmentInfo, Fragmentizer, LineEnding, LineParser, LiteralAnnouncement,
        MaxMessageSize,
    };
    use crate::fragmentizer::DecodeMessageError;

    #[test]
    fn fragmentizer_progress_nothing() {
        let mut fragmentizer = Fragmentizer::new(MaxMessageSize::Unlimited);

        let fragment_info = fragmentizer.progress();

        assert_eq!(fragment_info, None);
        assert_eq!(fragmentizer.message_bytes(), b"");
        assert!(!fragmentizer.is_message_complete());

        fragmentizer.enqueue_bytes(&[]);
        let fragment_info = fragmentizer.progress();

        assert_eq!(fragment_info, None);
        assert_eq!(fragmentizer.message_bytes(), b"");
        assert!(!fragmentizer.is_message_complete());
    }

    #[test]
    fn fragmentizer_progress_single_message() {
        let mut fragmentizer = Fragmentizer::new(MaxMessageSize::Unlimited);
        fragmentizer.enqueue_bytes(b"* OK ...\r\n");

        let fragment_info = fragmentizer.progress().unwrap();

        assert_eq!(
            fragment_info,
            FragmentInfo::Line {
                start: 0,
                end: 10,
                announcement: None,
                ending: LineEnding::CrLf,
            }
        );
        assert_eq!(fragmentizer.fragment_bytes(fragment_info), b"* OK ...\r\n");
        assert!(fragmentizer.is_message_complete());

        let fragment_info = fragmentizer.progress();

        assert_eq!(fragment_info, None);
        assert_eq!(fragmentizer.message_bytes(), b"");
        assert!(!fragmentizer.is_message_complete());
    }

    #[test]
    fn fragmentizer_progress_multiple_messages() {
        let mut fragmentizer = Fragmentizer::new(MaxMessageSize::Unlimited);
        fragmentizer.enqueue_bytes(b"A1 OK ...\r\n");
        fragmentizer.enqueue_bytes(b"A2 BAD ...\r\n");

        let fragment_info = fragmentizer.progress().unwrap();

        assert_eq!(
            fragment_info,
            FragmentInfo::Line {
                start: 0,
                end: 11,
                announcement: None,
                ending: LineEnding::CrLf,
            }
        );
        assert_eq!(fragmentizer.fragment_bytes(fragment_info), b"A1 OK ...\r\n");
        assert!(fragmentizer.is_message_complete());

        let fragment_info = fragmentizer.progress().unwrap();

        assert_eq!(
            fragment_info,
            FragmentInfo::Line {
                start: 0,
                end: 12,
                announcement: None,
                ending: LineEnding::CrLf,
            }
        );
        assert_eq!(
            fragmentizer.fragment_bytes(fragment_info),
            b"A2 BAD ...\r\n"
        );
        assert!(fragmentizer.is_message_complete());

        let fragment_info = fragmentizer.progress();

        assert_eq!(fragment_info, None);
        assert_eq!(fragmentizer.message_bytes(), b"");
        assert!(!fragmentizer.is_message_complete());
    }

    #[test]
    fn fragmentizer_progress_multiple_messages_with_lf() {
        let mut fragmentizer = Fragmentizer::new(MaxMessageSize::Unlimited);
        fragmentizer.enqueue_bytes(b"A1 NOOP\n");
        fragmentizer.enqueue_bytes(b"A2 LOGIN {5}\n");
        fragmentizer.enqueue_bytes(b"ABCDE");
        fragmentizer.enqueue_bytes(b" EFGIJ\n");

        let fragment_info = fragmentizer.progress().unwrap();

        assert_eq!(
            fragment_info,
            FragmentInfo::Line {
                start: 0,
                end: 8,
                announcement: None,
                ending: LineEnding::Lf,
            }
        );
        assert_eq!(fragmentizer.fragment_bytes(fragment_info), b"A1 NOOP\n");
        assert!(fragmentizer.is_message_complete());

        let fragment_info = fragmentizer.progress().unwrap();

        assert_eq!(
            fragment_info,
            FragmentInfo::Line {
                start: 0,
                end: 13,
                announcement: Some(LiteralAnnouncement {
                    mode: LiteralMode::Sync,
                    length: 5
                }),
                ending: LineEnding::Lf,
            }
        );
        assert_eq!(
            fragmentizer.fragment_bytes(fragment_info),
            b"A2 LOGIN {5}\n"
        );
        assert!(!fragmentizer.is_message_complete());

        let fragment_info = fragmentizer.progress().unwrap();

        assert_eq!(fragment_info, FragmentInfo::Literal { start: 13, end: 18 });
        assert_eq!(fragmentizer.fragment_bytes(fragment_info), b"ABCDE");
        assert!(!fragmentizer.is_message_complete());

        let fragment_info = fragmentizer.progress().unwrap();

        assert_eq!(
            fragment_info,
            FragmentInfo::Line {
                start: 18,
                end: 25,
                announcement: None,
                ending: LineEnding::Lf,
            }
        );
        assert_eq!(fragmentizer.fragment_bytes(fragment_info), b" EFGIJ\n");
        assert!(fragmentizer.is_message_complete());

        let fragment_info = fragmentizer.progress();

        assert_eq!(fragment_info, None);
        assert_eq!(fragmentizer.message_bytes(), b"");
        assert!(!fragmentizer.is_message_complete());
    }

    #[test]
    fn fragmentizer_progress_message_with_multiple_literals() {
        let mut fragmentizer = Fragmentizer::new(MaxMessageSize::Unlimited);
        fragmentizer.enqueue_bytes(b"A1 LOGIN {5}\r\n");
        fragmentizer.enqueue_bytes(b"ABCDE");
        fragmentizer.enqueue_bytes(b" {5}\r\n");
        fragmentizer.enqueue_bytes(b"FGHIJ");
        fragmentizer.enqueue_bytes(b"\r\n");

        let fragment_info = fragmentizer.progress().unwrap();

        assert_eq!(
            fragment_info,
            FragmentInfo::Line {
                start: 0,
                end: 14,
                announcement: Some(LiteralAnnouncement {
                    mode: LiteralMode::Sync,
                    length: 5,
                }),
                ending: LineEnding::CrLf,
            }
        );
        assert_eq!(
            fragmentizer.fragment_bytes(fragment_info),
            b"A1 LOGIN {5}\r\n"
        );
        assert!(!fragmentizer.is_message_complete());

        let fragment_info = fragmentizer.progress().unwrap();

        assert_eq!(fragment_info, FragmentInfo::Literal { start: 14, end: 19 });
        assert_eq!(fragmentizer.fragment_bytes(fragment_info), b"ABCDE");
        assert!(!fragmentizer.is_message_complete());

        let fragment_info = fragmentizer.progress().unwrap();

        assert_eq!(
            fragment_info,
            FragmentInfo::Line {
                start: 19,
                end: 25,
                announcement: Some(LiteralAnnouncement {
                    mode: LiteralMode::Sync,
                    length: 5,
                }),
                ending: LineEnding::CrLf,
            }
        );
        assert_eq!(fragmentizer.fragment_bytes(fragment_info), b" {5}\r\n");
        assert!(!fragmentizer.is_message_complete());

        let fragment_info = fragmentizer.progress().unwrap();

        assert_eq!(fragment_info, FragmentInfo::Literal { start: 25, end: 30 });
        assert_eq!(fragmentizer.fragment_bytes(fragment_info), b"FGHIJ");
        assert!(!fragmentizer.is_message_complete());

        let fragment_info = fragmentizer.progress().unwrap();

        assert_eq!(
            fragment_info,
            FragmentInfo::Line {
                start: 30,
                end: 32,
                announcement: None,
                ending: LineEnding::CrLf,
            }
        );
        assert_eq!(fragmentizer.fragment_bytes(fragment_info), b"\r\n");
        assert!(fragmentizer.is_message_complete());

        let fragment_info = fragmentizer.progress();

        assert_eq!(fragment_info, None);
        assert_eq!(fragmentizer.message_bytes(), b"");
        assert!(!fragmentizer.is_message_complete());
    }

    #[test]
    fn fragmentizer_progress_message_and_skip_after_literal_announcement() {
        let mut fragmentizer = Fragmentizer::new(MaxMessageSize::Unlimited);
        fragmentizer.enqueue_bytes(b"A1 LOGIN {5}\r\n");
        fragmentizer.enqueue_bytes(b"A2 NOOP\r\n");

        let fragment_info = fragmentizer.progress().unwrap();

        assert_eq!(
            fragment_info,
            FragmentInfo::Line {
                start: 0,
                end: 14,
                announcement: Some(LiteralAnnouncement {
                    mode: LiteralMode::Sync,
                    length: 5,
                }),
                ending: LineEnding::CrLf,
            }
        );
        assert_eq!(
            fragmentizer.fragment_bytes(fragment_info),
            b"A1 LOGIN {5}\r\n"
        );
        assert!(!fragmentizer.is_message_complete());

        fragmentizer.skip_message();

        let fragment_info = fragmentizer.progress().unwrap();

        assert_eq!(
            fragment_info,
            FragmentInfo::Line {
                start: 0,
                end: 9,
                announcement: None,
                ending: LineEnding::CrLf,
            }
        );
        assert_eq!(fragmentizer.fragment_bytes(fragment_info), b"A2 NOOP\r\n");
        assert!(fragmentizer.is_message_complete());

        let fragment_info = fragmentizer.progress();

        assert_eq!(fragment_info, None);
        assert_eq!(fragmentizer.message_bytes(), b"");
        assert!(!fragmentizer.is_message_complete());
    }

    #[test]
    fn fragmentizer_progress_message_byte_by_byte() {
        let mut fragmentizer = Fragmentizer::new(MaxMessageSize::Unlimited);
        let mut bytes = VecDeque::new();
        bytes.extend(b"A1 LOGIN {5}\r\n");
        bytes.extend(b"ABCDE");
        bytes.extend(b" FGHIJ\r\n");

        for _ in 0..14 {
            let fragment_info = fragmentizer.progress();

            assert_eq!(fragment_info, None);
            assert!(!fragmentizer.is_message_complete());

            fragmentizer.enqueue_bytes(&[bytes.pop_front().unwrap()]);
        }

        let fragment_info = fragmentizer.progress().unwrap();

        assert_eq!(
            fragment_info,
            FragmentInfo::Line {
                start: 0,
                end: 14,
                announcement: Some(LiteralAnnouncement {
                    mode: LiteralMode::Sync,
                    length: 5,
                }),
                ending: LineEnding::CrLf,
            }
        );
        assert_eq!(
            fragmentizer.fragment_bytes(fragment_info),
            b"A1 LOGIN {5}\r\n"
        );
        assert!(!fragmentizer.is_message_complete());

        for _ in 0..5 {
            let fragment_info = fragmentizer.progress();

            assert_eq!(fragment_info, None);
            assert!(!fragmentizer.is_message_complete());

            fragmentizer.enqueue_bytes(&[bytes.pop_front().unwrap()]);
        }

        let fragment_info = fragmentizer.progress().unwrap();

        assert_eq!(fragment_info, FragmentInfo::Literal { start: 14, end: 19 });
        assert_eq!(fragmentizer.fragment_bytes(fragment_info), b"ABCDE");
        assert!(!fragmentizer.is_message_complete());

        for _ in 0..8 {
            let fragment_info = fragmentizer.progress();

            assert_eq!(fragment_info, None);
            assert!(!fragmentizer.is_message_complete());

            fragmentizer.enqueue_bytes(&[bytes.pop_front().unwrap()]);
        }

        let fragment_info = fragmentizer.progress().unwrap();

        assert_eq!(
            fragment_info,
            FragmentInfo::Line {
                start: 19,
                end: 27,
                announcement: None,
                ending: LineEnding::CrLf,
            }
        );
        assert_eq!(fragmentizer.fragment_bytes(fragment_info), b" FGHIJ\r\n");
        assert!(fragmentizer.is_message_complete());

        let fragment_info = fragmentizer.progress();

        assert_eq!(fragment_info, None);
        assert_eq!(fragmentizer.message_bytes(), b"");
        assert!(!fragmentizer.is_message_complete());
    }

    #[track_caller]
    fn assert_is_line(
        unprocessed_bytes: &[u8],
        line_byte_count: usize,
        expected_announcement: Option<LiteralAnnouncement>,
        expected_ending: LineEnding,
    ) {
        let mut line_parser = LineParser::new(0);
        let unprocessed_bytes = unprocessed_bytes.iter().copied().collect();

        let (parsed_byte_count, fragment_info) = line_parser.parse(&unprocessed_bytes);

        assert_eq!(parsed_byte_count, line_byte_count);

        let Some(FragmentInfo::Line {
            start,
            end,
            announcement,
            ending,
        }) = fragment_info
        else {
            panic!("Unexpected fragment: {fragment_info:?}");
        };

        assert_eq!(start, 0);
        assert_eq!(end, line_byte_count);
        assert_eq!(announcement, expected_announcement);
        assert_eq!(ending, expected_ending);
    }

    #[test]
    fn fragmentizer_progress_multiple_messages_longer_than_max_size() {
        let mut fragmentizer = Fragmentizer::new(MaxMessageSize::Limited(17));
        fragmentizer.enqueue_bytes(b"A1 NOOP\r\n");
        fragmentizer.enqueue_bytes(b"A2 LOGIN ABCDE EFGIJ\r\n");
        fragmentizer.enqueue_bytes(b"A3 LOGIN {5}\r\n");
        fragmentizer.enqueue_bytes(b"ABCDE");
        fragmentizer.enqueue_bytes(b" EFGIJ\r\n");
        fragmentizer.enqueue_bytes(b"A4 LOGIN A B\r\n");

        let fragment_info = fragmentizer.progress().unwrap();

        assert_eq!(
            fragment_info,
            FragmentInfo::Line {
                start: 0,
                end: 9,
                announcement: None,
                ending: LineEnding::CrLf,
            }
        );
        assert_eq!(fragmentizer.fragment_bytes(fragment_info), b"A1 NOOP\r\n");
        assert_eq!(fragmentizer.message_bytes(), b"A1 NOOP\r\n");
        assert!(fragmentizer.is_message_complete());
        assert!(!fragmentizer.is_max_message_size_exceeded());

        let fragment_info = fragmentizer.progress().unwrap();

        assert_eq!(
            fragment_info,
            FragmentInfo::Line {
                start: 0,
                end: 22,
                announcement: None,
                ending: LineEnding::CrLf,
            }
        );
        assert_eq!(
            fragmentizer.fragment_bytes(fragment_info),
            b"A2 LOGIN ABCDE EF"
        );
        assert_eq!(fragmentizer.message_bytes(), b"A2 LOGIN ABCDE EF");
        assert!(fragmentizer.is_message_complete());
        assert!(fragmentizer.is_max_message_size_exceeded());

        let fragment_info = fragmentizer.progress().unwrap();

        assert_eq!(
            fragment_info,
            FragmentInfo::Line {
                start: 0,
                end: 14,
                announcement: Some(LiteralAnnouncement {
                    mode: LiteralMode::Sync,
                    length: 5
                }),
                ending: LineEnding::CrLf,
            }
        );
        assert_eq!(
            fragmentizer.fragment_bytes(fragment_info),
            b"A3 LOGIN {5}\r\n"
        );
        assert_eq!(fragmentizer.message_bytes(), b"A3 LOGIN {5}\r\n");
        assert!(!fragmentizer.is_message_complete());
        assert!(!fragmentizer.is_max_message_size_exceeded());

        let fragment_info = fragmentizer.progress().unwrap();

        assert_eq!(fragment_info, FragmentInfo::Literal { start: 14, end: 19 });
        assert_eq!(fragmentizer.fragment_bytes(fragment_info), b"ABC");
        assert_eq!(fragmentizer.message_bytes(), b"A3 LOGIN {5}\r\nABC");
        assert!(!fragmentizer.is_message_complete());
        assert!(fragmentizer.is_max_message_size_exceeded());

        let fragment_info = fragmentizer.progress().unwrap();

        assert_eq!(
            fragment_info,
            FragmentInfo::Line {
                start: 19,
                end: 27,
                announcement: None,
                ending: LineEnding::CrLf,
            }
        );
        assert_eq!(fragmentizer.fragment_bytes(fragment_info), b"");
        assert_eq!(fragmentizer.message_bytes(), b"A3 LOGIN {5}\r\nABC");
        assert!(fragmentizer.is_message_complete());
        assert!(fragmentizer.is_max_message_size_exceeded());

        let fragment_info = fragmentizer.progress().unwrap();

        assert_eq!(
            fragment_info,
            FragmentInfo::Line {
                start: 0,
                end: 14,
                announcement: None,
                ending: LineEnding::CrLf,
            }
        );
        assert_eq!(
            fragmentizer.fragment_bytes(fragment_info),
            b"A4 LOGIN A B\r\n"
        );
        assert_eq!(fragmentizer.message_bytes(), b"A4 LOGIN A B\r\n");
        assert!(fragmentizer.is_message_complete());
        assert!(!fragmentizer.is_max_message_size_exceeded());

        let fragment_info = fragmentizer.progress();

        assert_eq!(fragment_info, None);
        assert_eq!(fragmentizer.message_bytes(), b"");
        assert_eq!(fragmentizer.message_bytes(), b"");
        assert!(!fragmentizer.is_message_complete());
        assert!(!fragmentizer.is_max_message_size_exceeded());
    }

    #[test]
    fn fragmentizer_progress_messages_with_zero_max_size() {
        let mut fragmentizer = Fragmentizer::new(MaxMessageSize::Limited(0));
        fragmentizer.enqueue_bytes(b"A1 NOOP\r\n");
        fragmentizer.enqueue_bytes(b"A2 LOGIN ABCDE EFGIJ\r\n");
        fragmentizer.enqueue_bytes(b"A3 LOGIN {5}\r\n");
        fragmentizer.enqueue_bytes(b"ABCDE");
        fragmentizer.enqueue_bytes(b" EFGIJ\r\n");

        let fragment_info = fragmentizer.progress().unwrap();

        assert_eq!(
            fragment_info,
            FragmentInfo::Line {
                start: 0,
                end: 9,
                announcement: None,
                ending: LineEnding::CrLf,
            }
        );
        assert_eq!(fragmentizer.fragment_bytes(fragment_info), b"");
        assert_eq!(fragmentizer.message_bytes(), b"");
        assert!(fragmentizer.is_message_complete());
        assert!(fragmentizer.is_max_message_size_exceeded());

        let fragment_info = fragmentizer.progress().unwrap();

        assert_eq!(
            fragment_info,
            FragmentInfo::Line {
                start: 0,
                end: 22,
                announcement: None,
                ending: LineEnding::CrLf,
            }
        );
        assert_eq!(fragmentizer.fragment_bytes(fragment_info), b"");
        assert_eq!(fragmentizer.message_bytes(), b"");
        assert!(fragmentizer.is_message_complete());
        assert!(fragmentizer.is_max_message_size_exceeded());

        let fragment_info = fragmentizer.progress().unwrap();

        assert_eq!(
            fragment_info,
            FragmentInfo::Line {
                start: 0,
                end: 14,
                announcement: Some(LiteralAnnouncement {
                    mode: LiteralMode::Sync,
                    length: 5
                }),
                ending: LineEnding::CrLf,
            }
        );
        assert_eq!(fragmentizer.fragment_bytes(fragment_info), b"");
        assert_eq!(fragmentizer.message_bytes(), b"");
        assert!(!fragmentizer.is_message_complete());
        assert!(fragmentizer.is_max_message_size_exceeded());

        let fragment_info = fragmentizer.progress().unwrap();

        assert_eq!(fragment_info, FragmentInfo::Literal { start: 14, end: 19 });
        assert_eq!(fragmentizer.fragment_bytes(fragment_info), b"");
        assert_eq!(fragmentizer.message_bytes(), b"");
        assert!(!fragmentizer.is_message_complete());
        assert!(fragmentizer.is_max_message_size_exceeded());

        let fragment_info = fragmentizer.progress().unwrap();

        assert_eq!(
            fragment_info,
            FragmentInfo::Line {
                start: 19,
                end: 27,
                announcement: None,
                ending: LineEnding::CrLf,
            }
        );
        assert_eq!(fragmentizer.fragment_bytes(fragment_info), b"");
        assert_eq!(fragmentizer.message_bytes(), b"");
        assert!(fragmentizer.is_message_complete());
        assert!(fragmentizer.is_max_message_size_exceeded());

        let fragment_info = fragmentizer.progress();

        assert_eq!(fragment_info, None);
        assert_eq!(fragmentizer.message_bytes(), b"");
        assert_eq!(fragmentizer.message_bytes(), b"");
        assert!(!fragmentizer.is_message_complete());
        assert!(!fragmentizer.is_max_message_size_exceeded());
    }

    #[test]
    fn fragmentizer_decode_message() {
        let mut fragmentizer = Fragmentizer::new(MaxMessageSize::Limited(10));
        fragmentizer.enqueue_bytes(b"A1 NOOP\r\n");
        fragmentizer.enqueue_bytes(b"A2 LOGIN ABCDE EFGIJ\r\n");

        let command_codec = CommandCodec::new();
        let response_codec = ResponseCodec::new();

        fragmentizer.progress();
        assert_eq!(
            fragmentizer.decode_message::<CommandCodec>(&command_codec),
            Ok(Command::new("A1", CommandBody::Noop).unwrap()),
        );
        assert_eq!(
            fragmentizer.decode_message::<ResponseCodec>(&response_codec),
            Err(DecodeMessageError::DecodingFailure(
                ResponseDecodeError::Failed
            )),
        );

        fragmentizer.progress();
        assert_eq!(
            fragmentizer.decode_message::<ResponseCodec>(&response_codec),
            Err(DecodeMessageError::MessageTooLong {
                initial: b"A2 LOGIN A"
            }),
        );
    }

    #[track_caller]
    fn assert_not_line(not_a_line_bytes: &[u8]) {
        let mut line_parser = LineParser::new(0);
        let not_a_line_bytes = not_a_line_bytes.iter().copied().collect();

        let (parsed_byte_count, fragment_info) = line_parser.parse(&not_a_line_bytes);

        assert_eq!(parsed_byte_count, not_a_line_bytes.len());
        assert_eq!(fragment_info, None);
    }

    #[test]
    fn parse_line_examples() {
        assert_not_line(b"");

        assert_not_line(b"foo");

        assert_is_line(b"\n", 1, None, LineEnding::Lf);

        assert_is_line(b"\r\n", 2, None, LineEnding::CrLf);

        assert_is_line(b"\n\r", 1, None, LineEnding::Lf);

        assert_is_line(b"foo\n", 4, None, LineEnding::Lf);

        assert_is_line(b"foo\r\n", 5, None, LineEnding::CrLf);

        assert_is_line(b"foo\n\r", 4, None, LineEnding::Lf);

        assert_is_line(b"foo\nbar\n", 4, None, LineEnding::Lf);

        assert_is_line(b"foo\r\nbar\r\n", 5, None, LineEnding::CrLf);

        assert_is_line(b"\r\nfoo\r\n", 2, None, LineEnding::CrLf);

        assert_is_line(
            b"{1}\r\n",
            5,
            Some(LiteralAnnouncement {
                length: 1,
                mode: LiteralMode::Sync,
            }),
            LineEnding::CrLf,
        );

        assert_is_line(
            b"{1}\n",
            4,
            Some(LiteralAnnouncement {
                length: 1,
                mode: LiteralMode::Sync,
            }),
            LineEnding::Lf,
        );

        assert_is_line(
            b"foo {1}\r\n",
            9,
            Some(LiteralAnnouncement {
                length: 1,
                mode: LiteralMode::Sync,
            }),
            LineEnding::CrLf,
        );

        assert_is_line(
            b"foo {2} {1}\r\n",
            13,
            Some(LiteralAnnouncement {
                length: 1,
                mode: LiteralMode::Sync,
            }),
            LineEnding::CrLf,
        );

        assert_is_line(b"foo {1} \r\n", 10, None, LineEnding::CrLf);

        assert_is_line(b"foo \n {1}\r\n", 5, None, LineEnding::Lf);

        assert_is_line(b"foo {1} foo\r\n", 13, None, LineEnding::CrLf);

        assert_is_line(b"foo {1\r\n", 8, None, LineEnding::CrLf);

        assert_is_line(b"foo 1}\r\n", 8, None, LineEnding::CrLf);

        assert_is_line(b"foo { 1}\r\n", 10, None, LineEnding::CrLf);

        assert_is_line(
            b"foo {{1}\r\n",
            10,
            Some(LiteralAnnouncement {
                length: 1,
                mode: LiteralMode::Sync,
            }),
            LineEnding::CrLf,
        );

        assert_is_line(
            b"foo {42}\r\n",
            10,
            Some(LiteralAnnouncement {
                length: 42,
                mode: LiteralMode::Sync,
            }),
            LineEnding::CrLf,
        );

        assert_is_line(
            b"foo {42+}\r\n",
            11,
            Some(LiteralAnnouncement {
                length: 42,
                mode: LiteralMode::NonSync,
            }),
            LineEnding::CrLf,
        );

        assert_is_line(
            b"foo +{42}\r\n",
            11,
            Some(LiteralAnnouncement {
                length: 42,
                mode: LiteralMode::Sync,
            }),
            LineEnding::CrLf,
        );

        assert_is_line(b"foo {+}\r\n", 9, None, LineEnding::CrLf);

        assert_is_line(b"foo {42++}\r\n", 12, None, LineEnding::CrLf);

        assert_is_line(b"foo {+42+}\r\n", 12, None, LineEnding::CrLf);

        assert_is_line(b"foo {+42}\r\n", 11, None, LineEnding::CrLf);

        assert_is_line(b"foo {42}+\r\n", 11, None, LineEnding::CrLf);

        assert_is_line(b"foo {-42}\r\n", 11, None, LineEnding::CrLf);

        assert_is_line(b"foo {42-}\r\n", 11, None, LineEnding::CrLf);

        assert_is_line(
            b"foo {4294967295}\r\n",
            18,
            Some(LiteralAnnouncement {
                length: 4294967295,
                mode: LiteralMode::Sync,
            }),
            LineEnding::CrLf,
        );

        assert_is_line(b"foo {4294967296}\r\n", 18, None, LineEnding::CrLf);
    }

    #[test]
    fn parse_line_corner_case() {
        // According to the IMAP RFC, this line does not announce a literal.
        // We thought intensively about this corner case and asked different people.
        // Our conclusion: This corner case is an oversight of the RFC authors and
        // doesn't appear in the wild. We ignore it for now. If this becomes an issue
        // in practice then we should implement a detection for "* OK", "* NO" and
        // "* BAD".
        assert_is_line(
            b"* OK {1}\r\n",
            10,
            Some(LiteralAnnouncement {
                length: 1,
                mode: LiteralMode::Sync,
            }),
            LineEnding::CrLf,
        );
    }

    #[test]
    fn parse_tag_examples() {
        assert_eq!(parse_tag(b"1 NOOP\r\n"), Tag::try_from("1").ok());
        assert_eq!(parse_tag(b"12 NOOP\r\n"), Tag::try_from("12").ok());
        assert_eq!(parse_tag(b"123 NOOP\r\n"), Tag::try_from("123").ok());
        assert_eq!(parse_tag(b"1234 NOOP\r\n"), Tag::try_from("1234").ok());
        assert_eq!(parse_tag(b"12345 NOOP\r\n"), Tag::try_from("12345").ok());

        assert_eq!(parse_tag(b"A1 NOOP\r\n"), Tag::try_from("A1").ok());
        assert_eq!(parse_tag(b"A1 NOOP"), Tag::try_from("A1").ok());
        assert_eq!(parse_tag(b"A1 "), Tag::try_from("A1").ok());
        assert_eq!(parse_tag(b"A1  "), Tag::try_from("A1").ok());
        assert_eq!(parse_tag(b"A1 \r\n"), Tag::try_from("A1").ok());
        assert_eq!(parse_tag(b"A1 \n"), Tag::try_from("A1").ok());
        assert_eq!(parse_tag(b"A1"), None);
        assert_eq!(parse_tag(b"A1\r\n"), None);
        assert_eq!(parse_tag(b"A1\n"), None);
        assert_eq!(parse_tag(b" \r\n"), None);
        assert_eq!(parse_tag(b"\r\n"), None);
        assert_eq!(parse_tag(b""), None);
        assert_eq!(parse_tag(b" A1 NOOP\r\n"), None);
    }
}
