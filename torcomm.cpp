#ifndef TORCOMM_CPP
#define TORCOMM_CPP

#include <iostream>

#include "settings.h"

int main()
{
	try {
		global_settings = Settings();
	} catch(...)
	{
			std::cout << std::endl << "nigga what";
	}
	std::cout << std::endl;
	return 0;
}

#endif /* TORCOMM_CPP */
