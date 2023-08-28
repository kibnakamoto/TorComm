#ifndef SETTINGS_H
#define SETTINGS_H
#include <fstream>
#include <jsoncpp/json/json.h>

#include <iostream>

// parse settings.json
class Settings
{
	public:
	std::string keys;
	bool save;
	bool tor;
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
	}
};

// define global settings so it can be accesssed without creating a new object everytime, only create objects when modyfing settings
Settings global_settings = Settings();

#endif /* SETTINGS_H */
