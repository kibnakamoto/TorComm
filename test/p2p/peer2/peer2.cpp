#include <iostream>
#include <string>
#include <cstring>
#include <coroutine>

#include <boost/asio/co_spawn.hpp>

#include "../../../message.h"
#include "../../../comm.h"

int main() {
  std::string connect_ip = "::1";
  uint16_t peer1_port = 52024; // 2 ports since using localhost
  uint16_t peer2_port = 52025;

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

    std::thread t1([&peer1, peer2_port, connect_ip] {
        peer1.accept([&](std::shared_ptr<boost::asio::ip::tcp::socket> socket) {
            std::cout << "\n[PEER 1] Accepted connection from " << socket->remote_endpoint() << std::endl;

            boost::asio::co_spawn(
                peer1.get_io_context(),
                [socket, &peer1]() -> boost::asio::awaitable<void> {
                    auto [len, type] = co_await peer1.recv_genesis(socket);
            
                    std::string data(len, '\0');
                    co_await peer1.recv(socket, data);
                    std::cout << "\n[PEER 1] Received Data: " << data << std::endl;
            
                    co_return;
                },
                boost::asio::detached
            );

            // std::cout << "\n\nLEN::::" << len << std::endl;
            // Handle ECDH here
        });

        // connector
        peer1.connect(connect_ip, peer2_port, [&](std::shared_ptr<boost::asio::ip::tcp::socket> socket) {
            std::cout << "\n[PEER 1] Connected to " << socket->remote_endpoint();
            // Send test message
            std::string msg = "Hello from peer 1!";
            peer1.send_genesis(socket, 18, 0);
            peer1.send(socket, msg);
        });
        peer1.start_async();
    });

    std::thread t2([&peer2, peer1_port, connect_ip] {
        peer2.accept([&](std::shared_ptr<boost::asio::ip::tcp::socket> socket) {
            std::cout << "\n[PEER 2] Accepted connection from " << socket->remote_endpoint() << std::endl;
            boost::asio::co_spawn(
                peer2.get_io_context(),
                [socket, &peer2]() -> boost::asio::awaitable<void> {
                    auto [len, type] = co_await peer2.recv_genesis(socket);
            
                    std::string data(len, '\0');
                    co_await peer2.recv(socket, data);
                    std::cout << "\n[PEER 2] Received Data: " << data << std::endl;
            
                    co_return;
                },
                boost::asio::detached
            );
            // handle ECDH here
        });
        peer2.start_async();

        peer2.connect(connect_ip, peer1_port, [&](std::shared_ptr<boost::asio::ip::tcp::socket> socket) {
            std::cout << "\n[PEER 2] Connected to " << socket->remote_endpoint();
            // Send test message
            std::string msg = "Hello from peer 2!";
            peer2.send_genesis(socket, 18, 0);
            peer2.send(socket, msg);
        });

    });
    
    
    // join both threads to see outputs
    t1.join();
    t2.join();

  // Keep running
  while (true) std::this_thread::sleep_for(std::chrono::seconds(1));
}
