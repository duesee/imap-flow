use std::time::Duration;

use flow_test::test_setup::TestSetup;
use imap_types::core::Text;

#[test]
fn noop() {
    let (rt, mut server, mut client) = TestSetup::default().setup_server();

    let greeting = b"* OK ...\r\n";
    rt.run2(server.send_greeting(greeting), client.receive(greeting));

    let noop = b"A1 NOOP\r\n";
    rt.run2(client.send(noop), server.receive_command(noop));

    let status = b"A1 OK ...\r\n";
    rt.run2(server.send_status(status), client.receive(status));
}

#[test]
fn noop_with_large_lines() {
    let mut setup = TestSetup::default();
    // Sending large messages takes some time, especially when running on a slow CI.
    setup.runtime_options.timeout = Some(Duration::from_secs(10));

    let (rt, mut server, mut client) = setup.setup_server();

    // This number seems to be larger than the TCP buffer, so server/client must
    // send/receive in parallel to prevent a dead lock.
    const LARGE: usize = 10 * 1024 * 1024;

    let greeting = &mut b"* OK ".to_vec();
    greeting.extend(vec![b'.'; LARGE]);
    greeting.extend(b"\r\n");
    rt.run2(server.send_greeting(&greeting), client.receive(&greeting));

    let noop = b"A1 NOOP\r\n";
    rt.run2(client.send(noop), server.receive_command(noop));

    let status = &mut b"A1 OK ".to_vec();
    status.extend(vec![b'.'; LARGE]);
    status.extend(b"\r\n");
    rt.run2(server.send_status(status), client.receive(status));
}

#[test]
fn gibberish_instead_of_command() {
    let (rt, mut server, mut client) = TestSetup::default().setup_server();

    let greeting = b"* OK ...\r\n";
    rt.run2(server.send_greeting(greeting), client.receive(greeting));

    let gibberish = b"I like bananas\r\n";
    rt.run2(
        client.send(gibberish),
        server.receive_error_because_malformed_message(gibberish),
    );
}

#[test]
fn command_with_missing_cr() {
    let (rt, mut server, mut client) = TestSetup::default().setup_server();

    let greeting = b"* OK ...\r\n";
    rt.run2(server.send_greeting(greeting), client.receive(greeting));

    // Command with missing \r
    let noop = b"A1 NOOP\n";
    rt.run2(
        client.send(noop),
        server.receive_error_because_expected_crlf_got_lf(noop),
    );
}

#[test]
fn crlf_relaxed() {
    let mut setup = TestSetup::default();
    setup.server_flow_options.crlf_relaxed = true;

    let (rt, mut server, mut client) = setup.setup_server();

    let greeting = b"* OK ...\r\n";
    rt.run2(server.send_greeting(greeting), client.receive(greeting));

    // Command with missing \r
    let noop = b"A1 NOOP\n";
    rt.run2(client.send(noop), server.receive_command(noop));

    let status = b"A1 OK ...\r\n";
    rt.run2(server.send_status(status), client.receive(status));

    // Command with \r still works
    let noop = b"A2 NOOP\r\n";
    rt.run2(client.send(noop), server.receive_command(noop));

    let status = b"A2 OK ...\r\n";
    rt.run2(server.send_status(status), client.receive(status));
}

#[test]
fn login_with_literal() {
    // The server will accept the literal ABCDE because it's smaller than the max size
    let max_literal_size_tests = [5, 6, 10, 100];

    for max_literal_size in max_literal_size_tests {
        let mut setup = TestSetup::default();
        setup.server_flow_options.literal_accept_text = Text::unvalidated("You shall pass");
        setup.server_flow_options.max_literal_size = max_literal_size;

        let (rt, mut server, mut client) = setup.setup_server();

        let greeting = b"* OK ...\r\n";
        rt.run2(server.send_greeting(greeting), client.receive(greeting));

        let login = b"A1 LOGIN {5}\r\nABCDE {5}\r\nFGHIJ\r\n";
        let continuation_request = b"+ You shall pass\r\n";
        rt.run2(
            async {
                client.send(&login[..14]).await;
                client.receive(continuation_request).await;
                client.send(&login[14..25]).await;
                client.receive(continuation_request).await;
                client.send(&login[25..]).await;
            },
            server.receive_command(login),
        );

        let status = b"A1 NO ...\r\n";
        rt.run2(server.send_status(status), client.receive(status));
    }
}

#[test]
fn login_with_rejected_literal() {
    // The server will reject the literal ABCDE because it's larger than the max size
    let max_literal_size_tests = [0, 1, 4];

    for max_literal_size in max_literal_size_tests {
        let mut setup = TestSetup::default();
        setup.server_flow_options.literal_reject_text = Text::unvalidated("You shall not pass");
        setup.server_flow_options.max_literal_size = max_literal_size;

        let (rt, mut server, mut client) = setup.setup_server();

        let greeting = b"* OK ...\r\n";
        rt.run2(server.send_greeting(greeting), client.receive(greeting));

        let login = b"A1 LOGIN {5}\r\nABCDE {5}\r\nFGHIJ\r\n";
        rt.run2(
            client.send(&login[..14]),
            server.receive_error_because_literal_too_long(&login[..14]),
        );

        let status = b"A1 BAD You shall not pass\r\n";
        rt.run2_and_select(client.receive(status), server.progress_internal_responses());
    }
}

#[test]
fn command_larger_than_max_command_size() {
    // The server will reject the command because it's larger than the max size
    let max_command_size_tests = [9, 10, 20, 100, 10 * 1024 * 1024];

    for max_command_size in max_command_size_tests {
        let mut setup = TestSetup::default();
        setup.server_flow_options.max_command_size = max_command_size as u32;

        let (rt, mut server, mut client) = setup.setup_server();

        let greeting = b"* OK ...\r\n";
        rt.run2(server.send_greeting(greeting), client.receive(greeting));

        // Command smaller than the max size can be received
        let small_command = b"A1 NOOP\r\n";
        rt.run2(
            client.send(small_command),
            server.receive_command(small_command),
        );

        // Command larger than the max size triggers an error
        let large_command = &vec![b'.'; max_command_size + 1];
        rt.run2(
            client.send(large_command),
            server.receive_error_because_command_too_long(&large_command[..max_command_size]),
        );
    }
}
