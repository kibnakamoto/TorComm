#include <fstream>
#include <jsoncpp/json/json.h>

#include <iostream>

// port or ip key
#define PORT_KEY 16
#define  IP_KEY 32

class Settings
{
	public:
	std::string keys;
	bool save;
	bool tor;
	Json::Value setting;

	Settings()
	{
		update();
	}

	void update()
	{
		std::fstream settings("settings.json");
		settings >> setting;
		save = setting["save"].asBool();
		tor = setting["tor"].asBool();
		keys = setting["keys"].asString(); // private keys path
	}
};
