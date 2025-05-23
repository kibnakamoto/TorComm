#include <iostream>
#include <cassert>
#include <utility>
#include <fstream>

#include <boost/exception/diagnostic_information.hpp>

#include "../../comm.h"

// test Blocked class in comm.h

int main()
{
	Blocked blocked("../../security/keys", "../../blocked");
	blocked.block("0000:0000:0000:0000:0000:0000:0000:0001");
	blocked.block("0000:0000:0000:0000:0000:0000:0000:0002");
	blocked.block("0000:0000:0000:0000:0000:0000:0000:0003");

	bool blocked0 = blocked.is_blocked("0000:0000:0000:0000:0000:0000:0000:0001");
	bool blocked1 = blocked.is_blocked("0000:0000:0000:0000:0000:0000:0000:0002");
	bool blocked2 = blocked.is_blocked("0000:0000:0000:0000:0000:0000:0000:0003");
	bool blocked3 = blocked.is_blocked("0000:0000:0000:0000:0000:0000:0000:0004");
	assert(blocked0);
	assert(blocked1);
	assert(blocked2);
	assert(!blocked3);

	blocked0 = blocked.unblock("0000:0000:0000:0000:0000:0000:0000:0001");
	assert(blocked0); // should say it's blocked
	blocked0 = blocked.is_blocked("0000:0000:0000:0000:0000:0000:0000:0001");
	assert(!blocked0); // shouldn't be blocked again
	std::cout << std::endl << "PASSED - BLOCKED CLASS" << std::endl;

	std::ofstream file("../test.txt");
	file << 1;
	file.close();
	return 0;
}
