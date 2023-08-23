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
	Json::Value setting;

	Settings()
	{
		std::fstream settings("settings.json");
		settings >> setting;
		std::cout << "\n" << setting["save"] << "\n";
	}
};
