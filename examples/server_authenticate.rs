use std::error::Error;

use imap_codec::imap_types::response::{CommandContinuationRequest, Greeting, Status};
use imap_flow::{
    server::{ServerFlow, ServerFlowEvent, ServerFlowOptions},
    stream::AnyStream,
    types::CommandAuthenticate,
};
use tokio::net::TcpListener;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let (mut server, _) = {
        let stream = {
            let listener = TcpListener::bind("127.0.0.1:12345").await?;
            let (stream, _) = listener.accept().await?;
            stream
        };

        ServerFlow::send_greeting(
            AnyStream::new(stream),
            ServerFlowOptions::default(),
            Greeting::ok(None, "server_authenticate (example)")?,
        )
        .await?
    };

    let mut current_authenticate_tag = None;

    loop {
        let event = server.progress().await?;
        println!("{event:?}");

        // We don't implement any real SASL mechanism in this example.
        let pretend_to_need_more_data = rand::random();

        match event {
            ServerFlowEvent::CommandAuthenticateReceived {
                command_authenticate: CommandAuthenticate { tag, .. },
            } => {
                if pretend_to_need_more_data {
                    server
                        .authenticate_continue(CommandContinuationRequest::basic(
                            None,
                            "I need more data...",
                        )?)
                        .unwrap();

                    current_authenticate_tag = Some(tag);
                } else {
                    server
                        .authenticate_finish(Status::ok(
                            Some(tag),
                            None,
                            "Thanks, that's already enough!",
                        )?)
                        .unwrap();
                }
            }
            ServerFlowEvent::AuthenticateDataReceived { .. } => {
                if pretend_to_need_more_data {
                    server
                        .authenticate_continue(CommandContinuationRequest::basic(
                            None,
                            "...more...",
                        )?)
                        .unwrap();
                } else {
                    let tag = current_authenticate_tag.take().unwrap();

                    server
                        .authenticate_finish(Status::ok(Some(tag), None, "Thanks!")?)
                        .unwrap();
                }
            }
            ServerFlowEvent::CommandReceived { command } => {
                server.enqueue_status(
                    Status::no(Some(command.tag), None, "Please use AUTHENTICATE").unwrap(),
                );
            }
            _ => {}
        }
    }
}
