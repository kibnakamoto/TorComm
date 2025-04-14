#include <iostream>
#include <string>
#include <cstring>
#include <coroutine>

#include <boost/asio/co_spawn.hpp>

#include "../../message.h"
#include "../../comm.h"

// test if the two computers can communicate a simple message
void test_basic()
{
}

int main() {
  std::string connect_ip = "::1";
  uint16_t peer1_port = 52024; // 2 ports since using localhost
  uint16_t peer2_port = 52025;
  uint16_t peer3_port = 52026;

  // initialize cryptography
  Cryptography::Curves curve = Cryptography::SECP256K1;
  Cryptography::CommunicationProtocol comm_protocol = Cryptography::ECIES_HMAC_AES256_CBC_SHA512;
  uint8_t protocol_no = (uint8_t)comm_protocol + curve;
  Cryptography::ProtocolData protocol(protocol_no);
  assert(protocol.error == NO_ERROR);

  Cryptography::Key key(protocol);
  Blocked blocked("../../../security/keys", "../../../blocked");

  // Listener
  //if (is_listener) {
    P2P peer1(peer1_port, blocked);
    P2P peer2(peer2_port, blocked);
    P2P peer3(peer3_port, blocked);

    std::thread t1([&peer1, peer2_port, connect_ip] {
        boost::asio::co_spawn(
            peer1.get_io_context(),
            [&peer1, connect_ip]() -> boost::asio::awaitable<void> {
                while(true) {
                    auto listener_socket = co_await peer1.accept();
                    std::cout << "\n[PEER 1] Accepted connection from " << listener_socket->remote_endpoint() << std::endl;

                    auto [len, type] = co_await peer1.recv_genesis(listener_socket);
                    std::string data(len, '\0');
                    co_await peer1.recv(listener_socket, data);
                    std::cout << "\n[PEER 1] Received Data: " << data << std::endl;
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
                std::cout << "\n[PEER 1] Connected to " << socket->remote_endpoint();

                // Send test message
                std::string msg = "Hello from peer 1!";

                // peer1.send_genesis(socket, msg.length(), 0);
                // peer1.send(socket, msg);

                // send to peers 2,3
                // peer1.send_genesis(msg.length(), 0);
                // peer1.send(msg);
            },
            boost::asio::detached
        );

        // connector
        boost::asio::co_spawn(
            peer1.get_io_context(),
            [&peer1, peer2_port, connect_ip]() -> boost::asio::awaitable<void> {
                auto socket = co_await peer1.connect(connect_ip, peer2_port+1);
                std::cout << "\n[PEER 1] Connected to " << socket->remote_endpoint();

                // Send test message
                std::string msg = "Hello from peer 1!";

                // peer1.send_genesis(socket, msg.length(), 0);
                // peer1.send(socket, msg);

                // send to peers 2,3
                peer1.send_genesis(msg.length(), 0);
                peer1.send(msg);
            },
            boost::asio::detached
        );
        peer1.start_async();
    });

    std::thread t2([&peer2, peer1_port, connect_ip] {
        // listener
        boost::asio::co_spawn(
            peer2.get_io_context(),
            [&peer2, connect_ip]() -> boost::asio::awaitable<void> {
                auto socket = co_await peer2.accept();
                std::cout << "\n[PEER 2] Accepted connection from " << socket->remote_endpoint() << std::endl;

                auto [len, type] = co_await peer2.recv_genesis(socket);
                std::string data(len, '\0');
                co_await peer2.recv(socket, data);
                std::cout << "\n[PEER 2] Received Data: " << data << std::endl;
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

    std::thread t3([&peer3, peer1_port, connect_ip] {
        // listener
        boost::asio::co_spawn(
            peer3.get_io_context(),
            [&peer3, connect_ip]() -> boost::asio::awaitable<void> {
                auto socket = co_await peer3.accept();
                std::cout << "\n[PEER 3] Accepted connection from " << socket->remote_endpoint() << std::endl;

                auto [len, type] = co_await peer3.recv_genesis(socket);
                 std::cout << "len = " << len << std::endl;
                std::string data(len, '\0');

                co_await peer3.recv(socket, data);
                std::cout << "\n[PEER 3] Received Data: " << data << std::endl;
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
    
    
    // join both threads to see outputs
    t1.join();
    t2.join();
    t3.join();


  // Keep running
  while (true) std::this_thread::sleep_for(std::chrono::seconds(1));
}
