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
  * Description: For secure local-key management. This is for encrypting local data in configure.json files
  */

#ifndef KEYS_H
#define KEYS_H

#include <string>
#include <stdint.h>
#include <iomanip>
#include <optional>

#include <json/json.h>

// read keys from file
struct LocalKeys
{
	uint8_t* keys;
	uint16_t key_len;
	uint16_t pepper_len;
	uint16_t ports_key_len; 
	uint16_t keys_len; // total length of keys, length of keys pointer

	LocalKeys(std::string keys_path);

	~LocalKeys()
	{
		delete[] keys;
	}

	uint8_t *get_pepper();
	uint8_t *get_key();
	uint8_t *get_port_key();
};

std::string to_hex_str(uint8_t *ptr, uint16_t ptr_len);

// convert any unsigned num to hex-string
std::string to_hex_str(auto num)
{
	std::stringstream ss;
	if constexpr(sizeof(num) == 1)
		ss << std::hex << std::setfill('0') << std::setw(2) << num+0;
	else
		ss << std::hex << std::setfill('0') << std::setw(sizeof(num)<<1) << num;
	return ss.str();
}

// convert hex-string to any unsigned num
void hex_str_to(std::string num, auto &out)
{
	std::stringstream ss;
	ss << num;
	ss >> out;
}

uint16_t hex_str_to(std::string str, uint8_t *ptr);

void parse_ipv4(uint8_t *out, std::string ip);

void parse_ipv6(uint8_t *out, std::string ip);

std::string get_ipv6();

void init_configure_json(std::string config_path);


class Configure
{
	public:
		uint16_t port;
		uint16_t tor_port;
			
		// not relating to specific protocols. This is just for communications

		std::string public_ip;
		std::string *other_public_ips; // other ips
		uint32_t node_count;
		Json::Value config;
		std::string config_path;
		uint8_t **IVs; // IVs for all ips and ports in configuration.json
		enum IV {PORT, TOR_PORT, PUBLIC, PUBLIC_1}; // indexing of iv

		Configure(std::string configpath);

		// Configure to json value
		Configure(std::string configpath, Json::Value _config);

		uint32_t get_node_count();

		// destructor
		~Configure();

		// assign variables to config
		void get_values();

		// reset config to file
		void reset();

		// write member values back
		void write_values();

		// call write_values() to assign object members to config then call this function to write to file
		void write_to_file();

		// generate 6 new IVs for encrypting config members
		// IVs are a nonce so save them in config and only use them once
		void new_ivs();

		// decrypt all
		void decrypt(std::string keys_path);

		void encrypt(std::string keys_path);

	protected:

		// encrypt/decrypt configure.json values in every session
		// config_path: the path of configure.json
		// keys_path: path of keys.txt
		// return config, call config.write_to_file() to save values
		void process(std::string keys_path);
};

#endif /* KEYS_H */
