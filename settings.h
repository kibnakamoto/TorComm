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
	Json::Value setting;

	Settings();

	void get_values();
	

	// reset to file
	void reset();

	// update json value setting to members
	void update();

	// write values back to file
	void write_values();
};
#endif /* SETTINGS_H */

