#include <iostream>
#include <string>

#include "../../../message.h"
#include "../../../comm.h"

const constexpr uint16_t port = 15000;

int main()
{
	Cryptography::Curves curve = Cryptography::SECP256K1;
	Cryptography::CommunicationProtocol comm_protocol = Cryptography::ECIES_HMAC_AES256_CBC_SHA512;
	uint8_t protocol_no = (uint8_t)comm_protocol + curve;
	Cryptography::ProtocolData protocol(protocol_no); // initialize
	assert(protocol.error == NO_ERROR); // check if there are any errors
	Cryptography::Key key(protocol);

	std::string their_ip = "2607:fea8:1f1b:3d00:878:e421:22:a7b";
	// std::string their_ip = "10.0.0.213";
	Blocked blocked = Blocked("../../../security/keys", "../../../blocked");
	P2P p2p = P2P(port, blocked);
	//p2p.accept();
	p2p.connect(their_ip, port, [&p2p, protocol, &key](boost::asio::ip::tcp::socket &socket) mutable {
		p2p.send_two_party_ecdh(socket, protocol, key);
	});
	p2p.start_async();
	return 0;
}
