use imap_codec::imap_types::response::{Greeting, Status};
use imap_flow::{
    server::{ServerFlow, ServerFlowEvent, ServerFlowOptions},
    stream::AnyStream,
};
use tokio::net::TcpListener;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let (mut server, _) = {
        let stream = {
            let listener = TcpListener::bind("127.0.0.1:12345").await.unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            stream
        };

        ServerFlow::send_greeting(
            AnyStream::new(stream),
            ServerFlowOptions::default(),
            Greeting::ok(None, "server (example)").unwrap(),
        )
        .await
        .unwrap()
    };

    let mut handle = None;

    loop {
        match server.progress().await.unwrap() {
            ServerFlowEvent::CommandReceived { command } => {
                println!("command received: {command:?}");
                handle = Some(
                    server.enqueue_status(Status::no(Some(command.tag), None, "...").unwrap()),
                );
            }
            ServerFlowEvent::ResponseSent {
                handle: got_handle,
                response,
            } => {
                println!("response sent: {response:?}");
                assert_eq!(handle, Some(got_handle));
            }
            event => {
                println!("{event:?}");
            }
        }
    }
}
