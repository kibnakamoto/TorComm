#ifndef TORCOMM_CPP
#define TORCOMM_CPP

#include <boost/filesystem/operations.hpp>
#include <cstdio>
#include <iostream>

#include <boost/filesystem.hpp>

#include "settings.h"

int main()
{
	std::string keys_filename = "keys.txt";
	std::string current_path = boost::filesystem::current_path().string();
	std::string keys_path = current_path + "/" + keys_filename;
	if(!boost::filesystem::exists(keys_path)) { // if keys.txt exists
		// TODO: implement GUI
	}


	try {
		global_settings = Settings();
		global_settings.get_values();
		global_packet_size = global_settings.packet_size;
	} catch(Json::RuntimeError &e)
	{
		init_settings_json("./keys.txt");
		global_settings = Settings();
		global_settings.get_values();
		global_packet_size = global_settings.packet_size;
	}
	std::cout << std::endl;
	return 0;
}

#endif /* TORCOMM_CPP */
