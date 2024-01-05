 /* Copyright (c) 2023 Taha
  * this program is free software: you can redistribute it and/or modify
  * it under the terms of the gnu general public license as published by
  * the free software foundation, either version 3 of the license, or
  * (at your option) any later version.
  * this program is distributed in the hope that it will be useful,
  * but without any warranty; without even the implied warranty of
  * merchantability or fitness for a particular purpose.  see the
  * gnu general public license for more details.
  * you should have received a copy of the gnu general public license
  * along with this program.  if not, see <https://www.gnu.org/licenses/>.
  *
  * Author: Taha
  * Date: 2023, Dec 9
  * Description: Reading the settings.json file. For user selected settings.
  */

#include <string>
#include <fstream>

#include <json/json.h>

#include "settings.h"

void init_settings_json(std::string keys_path, std::string settings_path)
{
	std::ofstream file;
	Json::Value setting;
	setting["save"] = 1;
	setting["tor"] = 1;
	setting["keys"] = keys_path;
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
}

// write values back to file
void Settings::write_values()
{
	// write back to file
	std::fstream settings("settings.json", std::ios_base::out);
	settings << setting;
	
}
