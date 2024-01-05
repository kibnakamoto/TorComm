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

#ifndef SETTINGS_H
#define SETTINGS_H
#include <fstream>
#include <json/json.h>

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

