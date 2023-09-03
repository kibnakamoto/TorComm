#include <string>
#include <fstream>

#include <jsoncpp/json/json.h>

#include "settings.h"

void init_settings_json(std::string keys_path, std::string settings_path)
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

Settings::Settings()
{
	get_values();
}

void Settings::get_values()
{
	std::fstream settings("settings.json");
	settings >> setting;
	save = setting["save"].asBool();
	tor = setting["tor"].asBool();
	keys = setting["keys"].asString(); // private keys path
	packet_size = setting["packet"].asLargestUInt(); // private keys path
}

// reset to file
void Settings::reset()
{
	std::fstream settings("settings.json");
	settings >> setting;
	
}

// update json value setting to members
void Settings::update()
{
	setting["save"] = save;
	setting["keys"] = keys;
	setting["tor"] = tor;
	setting["packet_size"] = packet_size;
}

// write values back to file
void Settings::write_values()
{
	// write back to file
	std::fstream settings("settings.json", std::ios_base::out);
	settings << setting;
	
}
