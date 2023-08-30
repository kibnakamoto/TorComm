#ifndef SETTINGS_H
#define SETTINGS_H
#include <fstream>
#include <jsoncpp/json/json.h>

#include <iostream>

// recreate settings.json file if it is broken or doesn't exist
void init_settings_json(std::string keys_path, std::string settings_path="./settings.json")
{
	std::ofstream file;
	Json::Value setting;
	setting["save"] = 1;
	setting["tor"] = 1;
	setting["keys"] = keys_path;
	setting["packet_size"] = 1024;
	file.open(settings_path, std::ios_base::out | std::ofstream::trunc);
	file << setting;
}

// parse settings.json
class Settings
{
	public:
	std::string keys;
	bool save;
	bool tor;
	uint32_t packet_size;
	Json::Value setting;

	Settings()
	{
		get_values();
	}

	void get_values()
	{
		std::fstream settings("settings.json");
		settings >> setting;
		save = setting["save"].asBool();
		tor = setting["tor"].asBool();
		keys = setting["keys"].asString(); // private keys path
		packet_size = setting["packet"].asLargestUInt(); // private keys path
	}

	// reset to file
	void reset()
	{
		std::fstream settings("settings.json");
		settings >> setting;
		
	}

	// update json value setting to members
	void update()
	{
		setting["save"] = save;
		setting["keys"] = keys;
		setting["tor"] = tor;
		setting["packet_size"] = packet_size;
	}

	// write values back to file
	void write_values()
	{
		// write back to file
		std::fstream settings("settings.json", std::ios_base::out);
		settings << setting;
		
	}
};

// define global settings so it can be accesssed without creating a new object everytime, only create objects when modyfing settings
Settings global_settings; // TODO: don't initialize here, initialize with exception handling in torcomm.cpp, if error: call init_settings.json

uint32_t global_packet_size = global_settings.packet_size; // FOLLOW previous TODO

#endif /* SETTINGS_H */
