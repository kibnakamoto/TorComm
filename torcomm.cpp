#include <boost/filesystem/operations.hpp>
#include <cstdio>
#include <iostream>

#include <boost/filesystem.hpp>

#include "settings.h"
#include "keys.h"

	// TODO: MAJOR BUG DETECTED: ADD NO PADDING OPTION TO ALL AES ENCRYPTORS/DECRYPTORS. ALSO CHANGE PT SIZE TO CT SIZE ON PUT FUNCTION CALL - DONE
	// uses AES256_CBC
	// TODO: fix keys.cpp, redefine encryption because port key is now different - DONE
	// TODO: finish off securing the connect function in comm.cpp - DONE
	// TODO: define send/receive functions in P2P - DONE
	// NOT DONE:
	// TODO: define network packet construction and destruction (Packet class, PacketParser class)
	// TODO: define key exchanging for 2 peer communication 
	// TODO: define key exchanging for multi peer communication 
int main()
{
	std::string keys_filename = "keys.txt";
	std::string current_path = boost::filesystem::current_path().string();
	std::string keys_path = current_path + "/security/" + keys_filename;
	Settings settings;
	if(!boost::filesystem::exists(keys_path)) { // if keys.txt exists
		// TODO: implement GUI
	}

	// open and parse settings.json
	try {
		settings = Settings();
		settings.get_values();
	} catch(Json::RuntimeError &e) // if file doesn't exist
	{
		init_settings_json(keys_path);
		settings = Settings();
		settings.get_values();
	}
	

	std::cout << std::endl;
	return 0;
}
