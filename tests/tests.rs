use imap_codec::imap_types::{
    auth::AuthMechanism,
    command::{Command, CommandBody},
    core::Tag,
    response::{Greeting, Status},
};
use imap_flow::{
    client::{ClientFlow, ClientFlowEvent, ClientFlowOptions},
    server::{ServerFlow, ServerFlowEvent, ServerFlowOptions},
    stream::AnyStream,
};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn self_test() {
    let greeting = Greeting::ok(None, "Hello, World!").unwrap();

    // Port 0 means "pick any available port"
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = {
        let greeting = greeting.clone();

        async move {
            let (stream, _) = listener.accept().await.unwrap();

            let (mut server, _) = ServerFlow::send_greeting(
                AnyStream::new(stream),
                ServerFlowOptions::default(),
                greeting.clone(),
            )
            .await
            .unwrap();

            loop {
                match server.progress().await.unwrap() {
                    ServerFlowEvent::CommandReceived { command } => {
                        let no = Status::no(Some(command.tag), None, "...").unwrap();
                        server.enqueue_status(no);
                    }
                    ServerFlowEvent::CommandAuthenticateReceived {
                        command_authenticate,
                    } => {
                        let no = Status::no(Some(command_authenticate.tag), None, "...").unwrap();
                        server.enqueue_status(no);
                    }
                    _ => {}
                }
            }
        }
    };

    let _ = tokio::task::spawn(server);

    let (mut client, received_greeting) = {
        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        ClientFlow::receive_greeting(AnyStream::new(stream), ClientFlowOptions::default())
            .await
            .unwrap()
    };

    assert_eq!(greeting, received_greeting);

    client.enqueue_command(Command::new(Tag::unvalidated("A1"), CommandBody::Capability).unwrap());

    loop {
        match client.progress().await.unwrap() {
            ClientFlowEvent::StatusReceived { .. } => {
                client.enqueue_command(
                    Command::new(
                        Tag::unvalidated("A2"),
                        CommandBody::Authenticate {
                            mechanism: AuthMechanism::Plain,
                            initial_response: None,
                        },
                    )
                    .unwrap(),
                );
            }
            ClientFlowEvent::AuthenticateRejected { .. } => break,
            _ => {}
        }
    }
}
