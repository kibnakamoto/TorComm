#include <iostream>
#include <string>

#include "../../../message.h"
#include "../../../comm.h"

const constexpr uint16_t port = 15000;

int main()
{
	// std::string their_ip = "2607:fea8:1f1b:3d00:dde3:9b46:d5e7:ed70";
	// std::string their_ip = "2607:fea8:1f1b:3d00:878:e421:22:a7b";
	std::string their_ip = "10.0.0.213";
	Blocked blocked = Blocked("../../../security/keys", "../../../blocked");
	P2P p2p = P2P(port, blocked);
	//p2p.accept();
	p2p.connect(their_ip, port);
	p2p.start_async();
	return 0;
}
