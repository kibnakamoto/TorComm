#include <string>
#include <fstream>

#include <jsoncpp/json/json.h>

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
