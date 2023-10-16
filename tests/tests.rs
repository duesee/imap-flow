use imap_codec::imap_types::response::Greeting;
use imap_flow::{
    client::{ClientFlow, ClientFlowOptions},
    server::{ServerFlow, ServerFlowOptions},
    stream::Stream,
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

            ServerFlow::send_greeting(
                Stream::new(stream),
                ServerFlowOptions::default(),
                greeting.clone(),
            )
            .await
            .unwrap();
        }
    };

    let _ = tokio::task::spawn(server);

    let (_, received_greeting) = {
        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        ClientFlow::receive_greeting(Stream::new(stream), ClientFlowOptions::default())
            .await
            .unwrap()
    };

    assert_eq!(greeting, received_greeting);
}
