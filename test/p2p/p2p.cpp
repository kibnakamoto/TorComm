#include <iostream>
#include <string>
#include <cstring>
#include <coroutine>

#include <boost/asio/co_spawn.hpp>

#include "../../message.h"
#include "../../comm.h"

// test if the three peers can communicate a simple message, simple test. If these pass, then move on to 
// secure communication functions
bool test_basic(std::string connect_ip, Blocked &blocked)
{
    uint16_t peer1_port = 52024; // 3 ports since using localhost
    uint16_t peer2_port = 52025;
    uint16_t peer3_port = 52026;

    // 3 peers: 2 and 3 sends to 1, 1 sends to 2 and 3
    P2P peer1(peer1_port, blocked);
    P2P peer2(peer2_port, blocked);
    P2P peer3(peer3_port, blocked);

    // check if each test passed for the 3 peers (if they received the correct message)
    std::atomic<bool> passed1(true); // correctly receive from 2 and 3
    std::atomic<bool> passed2(true); // correctly receive from 1
    std::atomic<bool> passed3(true); // correctly receive from 1

    std::thread t1([&peer1, peer2_port, peer3_port, connect_ip, &passed1] {
        boost::asio::co_spawn(
            peer1.get_io_context(),
            [&peer1, connect_ip, &passed1]() -> boost::asio::awaitable<void> {
                bool first = 1; // which received is first
                while(true) {
                    auto listener_socket = co_await peer1.accept();
                    std::cout << "\n[PEER 1] Accepted connection from " << listener_socket->remote_endpoint() << std::endl;

                    auto [len, type] = co_await peer1.recv_genesis(listener_socket);
                    std::string data(len, '\0');
                    co_await peer1.recv(listener_socket, data);
                    std::cout << "\n[PEER 1] Received Data: " << data << std::endl;
                    if(data == "Hello from peer 2!") {
                        first = 0; // first is peer 2
                        continue;
                    }

                    // for the second data; if not peer 3 and not peer 2, then not passed
                    if(data != "Hello from peer 3!" && !first) {
                        passed1 = false;
                    }
                    // co_return;
                }
            },
            boost::asio::detached
        );

        // connector
        boost::asio::co_spawn(
            peer1.get_io_context(),
            [&peer1, peer2_port, connect_ip]() -> boost::asio::awaitable<void> {
                auto socket = co_await peer1.connect(connect_ip, peer2_port);
                std::cout << "\n[PEER 1] Connected to " << socket->remote_endpoint(); // connect to 1 peer
            },
            boost::asio::detached
        );

        // connector
        boost::asio::co_spawn(
            peer1.get_io_context(),
            [&peer1, peer3_port, connect_ip]() -> boost::asio::awaitable<void> {
                auto socket = co_await peer1.connect(connect_ip, peer3_port);
                std::cout << "\n[PEER 1] Connected to " << socket->remote_endpoint(); // connect to the other peer (2/3)

                // Send test message
                std::string msg = "Hello from peer 1!";

                // send to peers 2,3
                peer1.send_genesis(msg.length(), 0);
                peer1.send(msg);
            },
            boost::asio::detached
        );
        peer1.start_async();
    });

    std::thread t2([&peer2, peer1_port, connect_ip, &passed2] {
        // listener
        boost::asio::co_spawn(
            peer2.get_io_context(),
            [&peer2, connect_ip, &passed2]() -> boost::asio::awaitable<void> {
                auto socket = co_await peer2.accept();
                std::cout << "\n[PEER 2] Accepted connection from " << socket->remote_endpoint() << std::endl;

                auto [len, type] = co_await peer2.recv_genesis(socket);
                std::string data(len, '\0');
                co_await peer2.recv(socket, data);
                std::cout << "\n[PEER 2] Received Data: " << data << std::endl;
                if(data != "Hello from peer 1!")
                    passed2 = false;
                co_return;
            },
            boost::asio::detached
        );

        // connector
        boost::asio::co_spawn(
            peer2.get_io_context(),
            [&peer2, peer1_port, connect_ip]() -> boost::asio::awaitable<void> {
                auto socket = co_await peer2.connect(connect_ip, peer1_port);
                std::cout << "\n[PEER 2] Connected to " << socket->remote_endpoint();
                // Send test message
                std::string msg = "Hello from peer 2!";
                peer2.send_genesis(socket, msg.length(), 0);
                peer2.send(socket, msg);
            },
            boost::asio::detached
        );
        peer2.start_async();
    });

    std::thread t3([&peer3, peer1_port, connect_ip, &passed3] {
        // listener
        boost::asio::co_spawn(
            peer3.get_io_context(),
            [&peer3, connect_ip, &passed3]() -> boost::asio::awaitable<void> {
                auto socket = co_await peer3.accept();
                std::cout << "\n[PEER 3] Accepted connection from " << socket->remote_endpoint() << std::endl;

                auto [len, type] = co_await peer3.recv_genesis(socket);
                std::string data(len, '\0');

                co_await peer3.recv(socket, data);
                std::cout << "\n[PEER 3] Received Data: " << data << std::endl;
                if(data != "Hello from peer 1!")
                    passed3 = false;
                co_return;
            },
            boost::asio::detached
        );

        // connector
        boost::asio::co_spawn(
            peer3.get_io_context(),
            [&peer3, peer1_port, connect_ip]() -> boost::asio::awaitable<void> {
                auto socket = co_await peer3.connect(connect_ip, peer1_port);
                std::cout << "\n[PEER 3] Connected to " << socket->remote_endpoint();

                // Send test message
                std::string msg = "Hello from peer 3!";
                peer3.send_genesis(socket, msg.length(), 0);
                peer3.send(socket, msg);
            },
            boost::asio::detached
        );
        peer3.start_async();
    });
    
    // sleep for 3 seconds for the connections to happen, adjust if needed 
    std::this_thread::sleep_for(std::chrono::seconds(3));
    
    // join threads
    t1.join();
    t2.join();
    t3.join();

    bool passed = passed1 && passed2 && passed3;
    std::cout << "\n\n-----------------------------------------------------";
    if(passed) {
        std::cout << "\nPASSED All Basic Tests, Networking Functions Properly";
    } else {
        std::cout << "\nFAILED basic tests failed (t1, t2, t3): (" << passed1 << ", " << passed2 << ", " << passed3 << ")";
    }
    std::cout << "\n-----------------------------------------------------\n";
    std::cout << std::endl;
    return passed;
}

// advanced test for testing two-party full networking
bool advanced_test(std::string connect_ip, Blocked &blocked)
{
    // set ports
    uint16_t peer1_port = 52024; // 2 ports since using localhost
    uint16_t peer2_port = 52025;

    // 2 peers: 1 sends to 2 then 2 sends to 1.
    P2P peer1(peer1_port, blocked);
    P2P peer2(peer2_port, blocked);

    // check if each test passed for the 3 peers (if they received the correct message)
    // shared secrets
    std::atomic<uint8_t*> key1; // correctly receive from 2
    std::atomic<uint8_t*> key2; // correctly receive from 1
    std::atomic<uint16_t> keysize;

    std::thread t1([&peer1, peer2_port, connect_ip, &key1, &keysize] {

        // connector and acceptor
        boost::asio::co_spawn(
            peer1.get_io_context(),
            [&peer1, connect_ip, peer2_port, &key1, &keysize]() -> boost::asio::awaitable<void> {
                // set cryptography
                Cryptography::Curves curve = Cryptography::SECP256K1;
                Cryptography::CommunicationProtocol comm_protocol = Cryptography::ECIES_HMAC_AES256_CBC_SHA512;
                uint8_t protocol_no = (uint8_t)comm_protocol + curve;
                Cryptography::ProtocolData protocol(protocol_no);
                assert(protocol.error == NO_ERROR);
                Cryptography::Key key(protocol);
    
                auto listener_socket = co_await peer1.accept();
                std::cout << "\n[PEER 1] Accepted connection from " << listener_socket->remote_endpoint() << std::endl;

                auto socket = co_await peer1.connect(connect_ip, peer2_port);
                std::cout << "\n[PEER 1] Connected to " << socket->remote_endpoint(); // connect to 1 peer

                // ecdh
                auto sent = co_await peer1.send_two_party_ecdh(socket, protocol, key);
                std::cout << "\n[PEER 1] SEND STATUS: " << sent;
                
                // save key for testing
                key1 = new uint8_t[protocol.key_size];
                memcpy(key1, key.key, protocol.key_size);
                keysize = protocol.key_size;
                std::cout << "[PEER 1] key: ";
                for(int i=0;i<protocol.key_size;i++) {
                    std::cout << std::hex << key.key[i]+0;
                }
                std::cout << std::endl;
            },
            boost::asio::detached
        );
        peer1.start_async();
    });

    std::thread t2([&peer2, peer1_port, connect_ip, &key2] {
        // connector and acceptor
        boost::asio::co_spawn(
            peer2.get_io_context(),
            [&peer2, peer1_port, connect_ip, &key2]() -> boost::asio::awaitable<void> {
                Cryptography::ProtocolData protocol_received;
                Cryptography::Key key_received;
                auto socket = co_await peer2.connect(connect_ip, peer1_port);
                std::cout << "\n[PEER 2] Connected to " << socket->remote_endpoint(); // connect to 1 peer
        
                auto listener_socket = co_await peer2.accept();
                std::cout << "\n[PEER 2] Accepted connection from " << listener_socket->remote_endpoint() << std::endl;

                // ecdh
                ERRORS error = NO_ERROR;
                auto received = co_await peer2.recv_two_party_ecdh(listener_socket, protocol_received, key_received, error);
                std::cout << "\n[PEER 2] RECEIVE STATUS: " << received;
                if(error != NO_ERROR)
                    std::cout << "[PEER 2] ERROR ON ECDH RECEIVER" << ERROR_STRING[error];

                // save key for testing
                key2 = new uint8_t[protocol_received.key_size];
                memcpy(key2, key_received.key, protocol_received.key_size);
                std::cout << "[PEER 2] key: ";
                for(int i=0;i<protocol_received.key_size;i++) {
                    std::cout << std::hex << key_received.key[i]+0;
                }
                std::cout << std::endl;
            },
            boost::asio::detached
        );
        peer2.start_async();
    });
    
    // sleep for 3 seconds for the connections to happen, adjust if needed 
    std::this_thread::sleep_for(std::chrono::seconds(3));
    
    // join threads
    t1.join();
    t2.join();

    bool equal = true;
    for(uint16_t i=0;i<keysize;i++) {
        if(key1[i] != key2[i]) {
            equal = false;
            break;
        }
    }

    // if sent key = received key
    std::cout << "\n\n------------------------------------";
    if(equal) {
        std::cout << "\nPASSED Advanced Tests for Networking";
    } else {
        std::cout << "\nFAILED advanced tests for networking";
    }
    std::cout << "\n------------------------------------" << std::endl;
    delete[] key1;
    delete[] key2;

    return equal;
}

int main()
{
    Blocked blocked("../../security/keys", "../../blocked");
    std::string connect_ip = "::1";
    
    // test basic connections between 3 peers. Test if they can connect, send/recv
    bool basic_passed = test_basic(connect_ip, blocked);
    
    // if basic tests failed, don't continue with tests
    if(!basic_passed)
         return 1;
    
    // test full networking functions if basic tests passed
    // ecdh, encryption, verification.
    bool advanced_passed = advanced_test(connect_ip, blocked);

    if(!advanced_passed)
        return 1;

    std::cout << std::endl << "";
    
    // while (true) std::this_thread::sleep_for(std::chrono::seconds(1));
    return 0;
}
