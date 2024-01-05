#include <iostream>
#include <string>

#include "../../../message.h"
#include "../../../comm.h"

const constexpr uint16_t port = 1050;

int main()
{
	Blocked blocked = Blocked("../../../security/keys", "../../../blocked");
	P2P p2p = P2P(port, blocked);
	std::cout << std::endl << p2p.get_ip() << std::endl << std::flush;
	p2p.accept();
	// p2p.connect();
	p2p.start_async();
	return 0;
}