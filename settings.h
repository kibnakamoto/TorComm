#ifndef SETTINGS_H
#define SETTINGS_H
#include <fstream>
#include <jsoncpp/json/json.h>

#include <iostream>

// recreate settings.json file if it is broken or doesn't exist
void init_settings_json(std::string keys_path, std::string settings_path="./settings.json");

// parse settings.json

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
#endif /* SETTINGS_H */

