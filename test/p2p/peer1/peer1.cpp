#include <iostream>
#include <string>

#include "../../../message.h"
#include "../../../comm.h"

const constexpr uint16_t port = 15000;

// file for testing networking

int main()
{
	Cryptography::Curves curve = Cryptography::SECP256K1;
	Cryptography::CommunicationProtocol comm_protocol = Cryptography::ECIES_HMAC_AES256_CBC_SHA512;
	uint8_t protocol_no = (uint8_t)comm_protocol + curve;
	Cryptography::ProtocolData protocol(protocol_no); // initialize
	assert(protocol.error == NO_ERROR); // check if there are any errors, maybe add to errors.log if error exists

	Cryptography::Key key(protocol);


	std::string their_ip = ""; // test ipv6
	// std::string their_ip = "10.0.0.213"; // test ipv4
	Blocked blocked = Blocked("../../../security/keys", "../../../blocked");
	P2P p2p = P2P(port, blocked);
	p2p.accept([&p2p, protocol, &key](boost::asio::ip::tcp::socket &socket) mutable {
		std::cout << std::endl << "accepted connection successfully";
		//ERRORS error;
		//p2p.recv_two_party_ecdh(socket, protocol, key, error);
	});

	p2p.connect(their_ip, port, [&p2p, protocol, &key](boost::asio::ip::tcp::socket &socket) mutable {
		std::cout << std::endl << "p2p connection started successfully";
		// p2p.send_two_party_ecdh(socket, protocol, key);
	});

	p2p.start_async();
	return 0;
}
