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


#include <cryptopp/filters.h>
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>

#include "keys.h"
#include "settings.h"

#include <curl/curl.h>

#include <boost/asio/ip/address_v6.hpp>

#include <cryptopp/config_int.h>
#include <cryptopp/chacha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>

// Generate keys, and IVs for encrypting ports and IPs in configure.json in all sessions
// encrypt using ChaCha20 because it is a stream cipher, encrypt port and ip using private key

#define ZERO_IP "0000:0000:0000:0000:0000:0000:0000:0000"
#define DEFAULT_PORT 8000
#define PORT_TOR 9005

// TODO: in main file, make sure to design a secure join option, where a connection can be made where they request that you don't save ips. A secure connection mode where nothing is saved. Not even encrypted data. This means make config file optional

// read from keys file
LocalKeys::LocalKeys(std::string keys_path)
{
	std::ifstream keys_file(keys_path);
	std::string key;
	std::getline(keys_file, key);

	// get the lengths of key, pepper, port, and total length
	std::stringstream ss;
	std::string keys_lengths;
	std::getline(keys_file, keys_lengths);

	ss << std::hex << keys_lengths.substr(0, 4);
	ss >> key_len;
	ss.clear();

	ss << std::hex << keys_lengths.substr(4, 4);
	ss >> ports_key_len;
	ss.clear();

	ss << std::hex << keys_lengths.substr(8, 4);
	ss >> pepper_len;
	
	keys_len = key_len + ports_key_len + pepper_len;
	keys = new uint8_t[keys_len];
	
	CryptoPP::StringSource s(key, true, new CryptoPP::HexDecoder(new CryptoPP::ArraySink(keys, keys_len)));
}

uint8_t *LocalKeys::get_pepper()
{
	return &keys[key_len+ports_key_len];
}
uint8_t *LocalKeys::get_key()
{
	return keys;
}

uint8_t *LocalKeys::get_port_key()
{
	return &keys[key_len];
	
}

std::string to_hex_str(uint8_t *ptr, uint16_t ptr_len)
{
		std::stringstream ss;
		for(uint16_t i=0;i<ptr_len;i++) {
			ss << std::hex << std::setfill('0') << std::setw(2) << ptr[i]+0;
		}
		return ss.str();
}

// hex string to uint8_t*
// hex string must be padded and length should be a multiple of 2.
uint16_t hex_str_to(std::string str, uint8_t *ptr)
{
	uint16_t len = str.length()/2;
	for(uint16_t i=0;i<len;i++) {
		ptr[i] = std::strtol(str.substr(i*2, 2).c_str(), NULL, 16);
	}
	return len;
}

void parse_ipv4(uint8_t *out, std::string ip)
{
	// assign ip_key
	size_t keys_dot;
	uint8_t i=0;
	while ((keys_dot = ip.find('.')) != std::string::npos)
	{
		uint8_t byte = std::stoi(ip.substr(0, keys_dot));
		out[i] = byte;
	
	    ip.erase(0, keys_dot + 1);
		i++;
	}
	out[3] = std::stoi(ip);
}

void parse_ipv6(uint8_t *out, std::string ip)
{
	boost::asio::ip::address_v6 adr = boost::asio::ip::make_address_v6(ip);
	std::array<uint8_t, 16> tmp = adr.to_bytes();
	for(uint8_t i=0;i<16;i++) {out[i] = tmp[i];}
}

// helper function
static size_t write_call_back(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// get ipv6 address
std::string get_ipv6()
{
	 CURL *curl;
   std::string ret;

   curl = curl_easy_init();
   if(curl) {
     curl_easy_setopt(curl, CURLOPT_URL, "https://myexternalip.com/raw");
     curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_call_back);
	 curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ret);
	 curl_easy_perform(curl);
    curl_easy_cleanup(curl);
   }
   return ret;
}

// get public ipv4 address
// std::string get_ipv4()
// {
// 	 CURL *curl;
//    std::string ret;
// 
//    curl = curl_easy_init();
//    if(curl) {
//      curl_easy_setopt(curl, CURLOPT_URL, "http://www.myexternalip.com/raw");
//      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_call_back);
// 	 curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ret);
// 	 curl_easy_perform(curl);
//     curl_easy_cleanup(curl);
//    }
//    return ret;
// }


// parse configure.json in sessions, modify config for updating values
Configure::Configure(std::string configpath)
{
	config_path = configpath;
	std::fstream file(config_path);
	file >> config;
	node_count = get_node_count();

	IVs = new uint8_t*[node_count+4];
	for(uint8_t i=0;i<node_count+4;i++) IVs[i] = new uint8_t[CryptoPP::ChaCha::IV_LENGTH];
	other_public_ips = new std::string[node_count];
	get_values();
}

// set config, this is the default thing to use to make sure to NOT write to file unless Json::Value is encrypted
Configure::Configure(std::string configpath, Json::Value _config)
{

	config_path = configpath;
	config = _config;
	std::fstream file(config_path);
	file >> config;
	node_count = get_node_count();

	IVs = new uint8_t*[node_count+4];
	for(uint8_t i=0;i<node_count+4;i++) IVs[i] = new uint8_t[CryptoPP::ChaCha::IV_LENGTH];
	other_public_ips = new std::string[node_count];
	get_values();
}

// get the number of peers in the communication channel.
uint32_t Configure::get_node_count()
{
	uint32_t i=0;
	while (config.isMember(std::to_string(i))) i++;
	return i;
}

// destructor
Configure::~Configure()
{
	for(uint8_t i=0;i<node_count+4;i++) delete[] IVs[i];
	delete[] IVs;
	delete[] other_public_ips;
}

void Configure::get_values()
{
	//std::cout << std::endl << to_hex_str(*IVs, CryptoPP::ChaCha::IV_LENGTH) << std::endl;
	port = config["PORT"].asUInt();
	tor_port = config["TOR PORT"].asUInt();
	public_ip = config["PUBLIC"].asString();
	for(uint32_t i=0;i<node_count;i++) {
		other_public_ips[i] = config[std::to_string(i)].asString();
	}
	
	// get IVs
	hex_str_to(config["IV"]["PORT"].asString(), IVs[PORT]);
	hex_str_to(config["IV"]["TOR PORT"].asString(), IVs[TOR_PORT]);
	hex_str_to(config["IV"]["PUBLIC"].asString(), IVs[PUBLIC]);
	for(uint32_t i=0;i<node_count;i++) {
		hex_str_to(config["IV"][std::to_string(i)].asString(), IVs[i+PUBLIC_1]);
	}
}

// reset config to file
void Configure::reset()
{
	std::fstream file(config_path);
	file >> config;
}

// write member values back
void Configure::write_values()
{
	config["PORT"]      = port;
	config["TOR PORT"]  = tor_port;
	config["PUBLIC"]    = public_ip;
	for(uint32_t i=0;i<node_count;i++) {
		config[std::to_string(i)] = other_public_ips[i];
	}

	// IVs
	config["IV"]["PORT"] = to_hex_str(IVs[PORT], CryptoPP::ChaCha::IV_LENGTH);
	config["IV"]["TOR PORT"] = to_hex_str(IVs[TOR_PORT], CryptoPP::ChaCha::IV_LENGTH);
	config["IV"]["PUBLIC"] = to_hex_str(IVs[PUBLIC], CryptoPP::ChaCha::IV_LENGTH);
	for(uint32_t i=0;i<node_count;i++) {
		config["IV"][std::to_string(i)] = to_hex_str(IVs[i+PUBLIC_1], CryptoPP::ChaCha::IV_LENGTH);
	}
}

// call write_values() to assign object members to config then call this function to write to file
void Configure::write_to_file()
{
	// write back to file
	std::fstream file(config_path, std::ios_base::out);
	file << config;
}

// generate 6 new IVs for encrypting config members
// IVs are a nonce so save them in config and only use them once
void Configure::new_ivs()
{
	CryptoPP::AutoSeededRandomPool rng;
	rng.GenerateBlock((IVs[PORT]), CryptoPP::ChaCha::IV_LENGTH); // generate port IV
	rng.GenerateBlock((IVs[TOR_PORT]), CryptoPP::ChaCha::IV_LENGTH); // generate tor port IV
	rng.GenerateBlock((IVs[PUBLIC]), CryptoPP::ChaCha::IV_LENGTH); // generate public ip IV
	rng.GenerateBlock((IVs[PUBLIC_1]), CryptoPP::ChaCha::IV_LENGTH); // generate public ip 1 IV
	
	// set config
	config["IV"]["PORT"] = to_hex_str(IVs[PORT], CryptoPP::ChaCha::IV_LENGTH);
	config["IV"]["TOR PORT"] = to_hex_str(IVs[TOR_PORT], CryptoPP::ChaCha::IV_LENGTH);
	config["IV"]["PUBLIC"] = to_hex_str(IVs[PUBLIC], CryptoPP::ChaCha::IV_LENGTH);
	for(uint32_t i=0;i<node_count;i++) {
		config["IV"][std::to_string(i)] = to_hex_str(IVs[i+PUBLIC_1], CryptoPP::ChaCha::IV_LENGTH);
	}
}

// decrypt all
void Configure::decrypt(std::string keys_path)
{
	process(keys_path);
}

void Configure::encrypt(std::string keys_path)
{
	process(keys_path);
	write_to_file(); // if encrypt, write to file
}

// encrypt/decrypt configure.json values in every session
// config_path: the path of configure.json
// keys_path: path of keys.txt
// return config, call config.write_to_file() to save values
void Configure::process(std::string keys_path)
{
	LocalKeys local_key(keys_path);
	uint8_t *key = new uint8_t[local_key.keys_len];

	// encrypt all values in configure
	CryptoPP::ChaCha::Encryption chacha;
	

	// encrypt port
	uint8_t *str_port = new uint8_t[2];
	uint8_t port_len;

	 // convert port to bytearray
	if (port > 0xff) {
		str_port[0] = (uint8_t)(port >> 8);
		str_port[1] = (uint8_t)port;
		port_len = 2;
	} else {
		*str_port = (uint8_t)port;
		port_len = 1;
	}

	// encrypt port
	uint8_t *ct = new uint8_t[port_len];
	chacha.SetKeyWithIV(&key[local_key.key_len], local_key.ports_key_len, IVs[PORT]); // 16-bit chacha20 encryption key
	chacha.ProcessData(ct, str_port, port_len);
	port = ((uint16_t)ct[0] << 8) | ct[1];
	
	// encrypt/decrypt public ip, all IPs are encrypted byte by byte. the dots aren't encrypted
	ct = new uint8_t[16];
	uint8_t *ip = new uint8_t[16];
	parse_ipv6(ip, public_ip);
	chacha.SetKeyWithIV(key, local_key.key_len, IVs[PUBLIC]); // 256-bit chacha20 encryption key
	public_ip = "";
	for(uint8_t i=0;i<8;i++) {
		std::stringstream ss;
		chacha.ProcessData(&ct[i*2], &ip[i*2], 1);
		chacha.ProcessData(&ct[i*2+1], &ip[i*2+1], 1);
		//ss << std::hex << ((uint16_t)ct[i*2] << 8 | ct[i*2+1]);
		ss << std::setfill('0') << std::setw(2) << std::hex << ct[i*2]+0; 
		ss << std::setfill('0') << std::setw(2) << std::hex << ct[i*2+1]+0;
		public_ip += ss.str();
		
		if(i != 7) public_ip += ":";
	}

	// on other devices

	// encrypt/decrypt public ip 1 (other device)
	for(uint32_t n=0;n<node_count;n++) {
		parse_ipv6(ip, other_public_ips[n]);
		chacha.SetKeyWithIV(key, local_key.key_len, IVs[n+PUBLIC_1]); // 256-bit chacha20 encryption key
		other_public_ips[n] = "";
		for(uint8_t i=0;i<8;i++) {
			std::stringstream ss;
			chacha.ProcessData(&ct[i*2], &ip[i*2], 1);
			chacha.ProcessData(&ct[i*2+1], &ip[i*2+1], 1);
			//ss << std::hex << ((uint16_t)ct[i*2] << 8 | ct[i*2+1]);
			ss << std::setfill('0') << std::setw(2) << std::hex << ct[i*2]+0; 
			ss << std::setfill('0') << std::setw(2) << std::hex << ct[i*2+1]+0;
			other_public_ips[n] += ss.str();
			if(i != 7) other_public_ips[n] += ":";
		}
	}

	write_values();
	delete[] ip;
	delete[] key;
	delete[] ct;
}

// default configure.json file don't forget to update IVs
// generate file in new session
// returns decrypted version of configure.json
Json::Value init_configure_json(std::string config_path, std::string keys_path)
{
	CryptoPP::AutoSeededRandomPool rng;
	Json::Value json_conf;
	std::ofstream file;

	json_conf["0"] = ZERO_IP;
	json_conf["PUBLIC"] = get_ipv6();
	json_conf["PORT"] = DEFAULT_PORT;
	json_conf["TOR PORT"] = PORT_TOR;

	// generate and set IVs
	uint8_t *ptr = new uint8_t[CryptoPP::ChaCha::IV_LENGTH];
	rng.GenerateBlock(ptr, CryptoPP::ChaCha::IV_LENGTH); // generate port IV
	json_conf["IV"]["PORT"] = to_hex_str(ptr, CryptoPP::ChaCha::IV_LENGTH);
	rng.GenerateBlock(ptr, CryptoPP::ChaCha::IV_LENGTH); // generate tor port IV
	json_conf["IV"]["TOR PORT"] = to_hex_str(ptr, CryptoPP::ChaCha::IV_LENGTH);
	rng.GenerateBlock(ptr, CryptoPP::ChaCha::IV_LENGTH); // generate public ip IV
	json_conf["IV"]["PUBLIC"] = to_hex_str(ptr, CryptoPP::ChaCha::IV_LENGTH);
	rng.GenerateBlock(ptr, CryptoPP::ChaCha::IV_LENGTH); // generate public ip 1 IV
	json_conf["IV"]["0"] = to_hex_str(ptr, CryptoPP::ChaCha::IV_LENGTH);
	Configure config = Configure(config_path, json_conf);
	config.encrypt(keys_path);

	delete[] ptr;
	return json_conf;
}

// For testing keys
// int main()
// {
// 	try {
// 		global_settings = Settings();
// 		global_settings.get_values();
// 	} catch(Json::RuntimeError &e)
// 	{
// 		init_settings_json("security/keys.txt");
// 		global_settings = Settings();
// 		global_settings.get_values();
// 		global_packet_size = global_settings.packet_size;
// 	}
// 	//init_configure_json("./configure.json");
// 	Configure config = Configure("./configure.json");
// 	config.encrypt();
// 	return 0;
// }
