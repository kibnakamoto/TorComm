#include <iostream>

#include <utility>
#include "../comm.h"

// test blocked class

int main()
{
	Blocked blocked("../security/keys", "../blocked");
	blocked.block("0000:0000:0000:0000:0000:0000:0000:0000");
	blocked.block("0000:0000:0000:0000:0000:0000:0000:0001");
	blocked.block("0000:0000:0000:0000:0000:0000:0000:0002");
	//std::cout << std::endl << (blocked.is_blocked("0000:0000:0000:0000:0000:0000:0000:0000"));
	return 0;
}
