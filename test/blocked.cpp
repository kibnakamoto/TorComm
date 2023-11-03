#include <iostream>
#include <cassert>
#include <utility>

#include "../comm.h"

// test blocked class

int main()
{
	Blocked blocked("../security/keys", "../blocked");
	blocked.block("0000:0000:0000:0000:0000:0000:0000:0000");
	blocked.block("0000:0000:0000:0000:0000:0000:0000:0001");
	blocked.block("0000:0000:0000:0000:0000:0000:0000:0002");

	bool blocked0 = blocked.is_blocked("0000:0000:0000:0000:0000:0000:0000:0000");
	bool blocked1 = blocked.is_blocked("0000:0000:0000:0000:0000:0000:0000:0001");
	bool blocked2 = blocked.is_blocked("0000:0000:0000:0000:0000:0000:0000:0002");
	bool blocked3 = blocked.is_blocked("0000:0000:0000:0000:0000:0000:0000:0003");
	assert(blocked0);
	assert(blocked1);
	assert(blocked2);
	assert(!blocked3);

	blocked0 = blocked.unblock("0000:0000:0000:0000:0000:0000:0000:0000");
	assert(blocked0); // should say it's blocked
	blocked0 = blocked.is_blocked("0000:0000:0000:0000:0000:0000:0000:0000");
	assert(!blocked0); // shouldn't be blocked again
	std::cout << std::endl << "passed" << std::endl;
	return 0;
}
