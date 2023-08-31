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
	Settings settings;
	if(!boost::filesystem::exists(keys_path)) { // if keys.txt exists
		// TODO: implement GUI
	}

	try {
		settings = Settings();
		settings.get_values();
	} catch(Json::RuntimeError &e)
	{
		init_settings_json(keys_path);
		settings = Settings();
		settings.get_values();
	}
	std::cout << std::endl;
	return 0;
}

#endif /* TORCOMM_CPP */
