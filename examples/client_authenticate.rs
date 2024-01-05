use std::{collections::VecDeque, error::Error};

use imap_codec::imap_types::{
    auth::{AuthMechanism, AuthenticateData},
    command::{Command, CommandBody},
    secret::Secret,
};
use imap_flow::{
    client::{ClientFlow, ClientFlowEvent, ClientFlowOptions},
    stream::AnyStream,
};
use tag_generator::TagGenerator;
use tokio::net::TcpStream;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let stream = AnyStream::new(TcpStream::connect("127.0.0.1:12345").await?);

    let (mut client, greeting) =
        ClientFlow::receive_greeting(stream, ClientFlowOptions::default()).await?;

    println!("{greeting:?}");

    let mut tag_generator = TagGenerator::new();

    let tag = tag_generator.generate();
    client.enqueue_command(Command {
        tag: tag.clone(),
        body: CommandBody::authenticate(AuthMechanism::Login),
    });

    let mut authenticate_data = VecDeque::from([
        AuthenticateData::Continue(Secret::new(b"alice".to_vec())),
        AuthenticateData::Continue(Secret::new(b"password".to_vec())),
    ]);

    loop {
        let event = client.progress().await?;
        println!("{event:?}");

        match event {
            ClientFlowEvent::ContinuationAuthenticateReceived { .. } => {
                if let Some(authenticate_data) = authenticate_data.pop_front() {
                    client.authenticate_continue(authenticate_data).unwrap();
                } else {
                    client
                        .authenticate_continue(AuthenticateData::Cancel)
                        .unwrap();
                }
            }
            ClientFlowEvent::AuthenticateAccepted { .. } => {
                break;
            }
            ClientFlowEvent::AuthenticateRejected { .. } => {
                break;
            }
            _ => {}
        }
    }

    Ok(())
}
