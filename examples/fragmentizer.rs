use std::{io::Read, net::TcpStream};

use imap_codec::ResponseCodec;
use imap_next::fragmentizer::{FragmentInfo, Fragmentizer, MaxMessageSize};

fn main() {
    let mut stream = TcpStream::connect("127.0.0.1:12345").unwrap();
    let mut fragmentizer = Fragmentizer::new(MaxMessageSize::Limited(1024));
    let codec = ResponseCodec::default();

    println!("Receiving IMAP responses...\n");

    loop {
        // Progress message
        let fragment_info = fragmentizer.progress();

        if let Some(fragment_info) = fragment_info {
            // Handle line or literal fragment
            match fragment_info {
                FragmentInfo::Line {
                    announcement,
                    ending,
                    ..
                } => {
                    println!("Received line fragment");
                    println!("Literal announcement: {announcement:?}");
                    println!("Line ending: {ending:?}");
                }
                FragmentInfo::Literal { .. } => println!("Received literal fragment"),
            };

            // Handle fragment bytes
            println!(
                "Fragment bytes: {:?}",
                fragmentizer.fragment_bytes(fragment_info)
            );

            // Handle complete message
            if fragmentizer.is_message_complete() {
                match fragmentizer.decode_message(&codec) {
                    Ok(message) => println!("Decoded message: {message:#?}\n"),
                    Err(error) => println!("Decoding error: {error:?}\n"),
                }
            }
        } else {
            // Read more bytes
            let mut buffer = [0; 64];
            let count = stream.read(&mut buffer).unwrap();
            fragmentizer.enqueue_bytes(&buffer[0..count]);
        }
    }
}
