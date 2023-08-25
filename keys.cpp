#include <cryptopp/config_int.h>
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>

#include "keys.h"
#include "settings.h"

#include <cryptopp/chacha.h>
#include <cryptopp/osrng.h>

// 1. Generate keys for encrypting ports and IPs
//
// FORMAT:
// hex key
// e.g.
// ff.3e.4a.6b.45...
//
// encrypt using ChaCha20 because it is a stream cipher, encrypt port and ip using private key


// TODO: before writing to file, make sure to ask user to backup all keys before replacing
// TODO: make sure to decrypt all IPs and ports before replacing file

// generate new key in keys.txt file
void new_port_ip_key(Settings settings=global_settings)
{
	std::ofstream file;
    CryptoPP::AutoSeededRandomPool rng;

	file.open(settings.keys, std::ios_base::out);

	uint8_t *k = new uint8_t[32];
	rng.GenerateBlock(k, 32);
	for(uint8_t i=0;i<32;i++) {
		file << k[i]+0;
		if(i !=31)
			file << ".";
	}
}

// read key from keys.txt file
void get_port_ip_key(uint8_t *key, std::string keys_path=global_settings.keys)
{
	std::ifstream keys_file(keys_path);
	std::string keys;
	std::getline(keys_file, keys);
	size_t keys_dot = keys_dot = keys.find('.');
	
	uint8_t i=0;
	while ((keys_dot = keys.find('.')) != std::string::npos)
	{
		uint8_t byte = std::stoi(keys.substr(0, keys_dot));
		key[i] = byte;

	    keys.erase(0, keys_dot + 1);
		i++;
	}
	key[31] = std::stoi(keys);
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

void parse_ip(uint8_t *out, std::string ip)
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

// parse configure.json in sessions, modify config for updating values
class Configure
{
	public:
		uint16_t port;
		uint16_t tor_port;
		std::string public_ip;
		std::string private_ip;
		std::string public_b_ip;
		std::string private_b_ip;
		Json::Value config;
		std::string config_path;
		uint8_t **IVs = new uint8_t*[6]; // IVs for all ips and ports in configuration.json
		enum IV {PORT, TOR_PORT, PUBLIC, PRIVATE, PUBLIC_B, PRIVATE_B}; // indexing of iv

		Configure(std::string configpath)
		{
			for(uint8_t i=0;i<6;i++) IVs[i] = new uint8_t[CryptoPP::ChaCha::IV_LENGTH];

			config_path = configpath;
			std::fstream file(config_path);
			file >> config;
			get_values();
		}

		// destructor
		~Configure()
		{
			for(uint8_t i=0;i<6;i++) delete[] IVs[i];
			delete[] IVs;
		}

		void get_values()
		{
			//std::cout << std::endl << to_hex_str(*IVs, CryptoPP::ChaCha::IV_LENGTH) << std::endl;
			port = config["PORT"].asUInt();
			tor_port = config["TOR PORT"].asUInt();
			public_ip = config["PUBLIC"].asString();
			private_ip = config["PRIVATE"].asString();
			public_b_ip = config["PUBLIC B"].asString();
			private_b_ip = config["PRIVATE B"].asString();
			
			// get IVs
			hex_str_to(config["IV"]["PORT"].asString(), IVs[PORT]);
			hex_str_to(config["IV"]["TOR PORT"].asString(), IVs[TOR_PORT]);
			hex_str_to(config["IV"]["PUBLIC"].asString(), IVs[PUBLIC]);
			hex_str_to(config["IV"]["PRIVATE"].asString(), IVs[PRIVATE]);
			hex_str_to(config["IV"]["PUBLIC B"].asString(), IVs[PUBLIC_B]);
			hex_str_to(config["IV"]["PRIVATE B"].asString(), IVs[PRIVATE_B]);
		}

		// reset config to file
		void reset()
		{
			std::fstream file(config_path);
			file >> config;
		}

		// write member values back
		void write_values()
		{
			config["PORT"]      = port;
			config["TOR PORT"]  = tor_port;
			config["PUBLIC"]    = public_ip;
			config["PRIVATE"]   = private_ip;
			config["PUBLIC B"]  = public_b_ip;
			config["PRIVATE B"] = private_b_ip;

			// IVs
			config["IV"]["PORT"] = to_hex_str(IVs[PORT], CryptoPP::ChaCha::IV_LENGTH);
			config["IV"]["TOR PORT"] = to_hex_str(IVs[TOR_PORT], CryptoPP::ChaCha::IV_LENGTH);
			config["IV"]["PUBLIC"] = to_hex_str(IVs[PUBLIC], CryptoPP::ChaCha::IV_LENGTH);
			config["IV"]["PRIVATE"] = to_hex_str(IVs[PRIVATE], CryptoPP::ChaCha::IV_LENGTH);
			config["IV"]["PUBLIC B"] = to_hex_str(IVs[PUBLIC_B], CryptoPP::ChaCha::IV_LENGTH);
			config["IV"]["PRIVATE B"] = to_hex_str(IVs[PRIVATE_B], CryptoPP::ChaCha::IV_LENGTH);
		}

		// call write_values() to assign object members to config then call this function to write to file
		void write_to_file()
		{
			// write back to file
			std::fstream file(config_path, std::ios_base::out);
			file << config;
		}

		// generate 6 new IVs for encrypting config members
		void new_ivs()
		{
			CryptoPP::AutoSeededRandomPool rng;
			rng.GenerateBlock((IVs[PORT]), CryptoPP::ChaCha::IV_LENGTH); // generate port IV
			rng.GenerateBlock((IVs[TOR_PORT]), CryptoPP::ChaCha::IV_LENGTH); // generate tor port IV
			rng.GenerateBlock((IVs[PUBLIC]), CryptoPP::ChaCha::IV_LENGTH); // generate public ip IV
			rng.GenerateBlock((IVs[PRIVATE]), CryptoPP::ChaCha::IV_LENGTH); // generate private ip IV
			rng.GenerateBlock((IVs[PUBLIC_B]), CryptoPP::ChaCha::IV_LENGTH); // generate public ip B IV
			rng.GenerateBlock((IVs[PRIVATE_B]), CryptoPP::ChaCha::IV_LENGTH); // generate private ip B IV
			
			// set config
			config["IV"]["PORT IV"] = to_hex_str(IVs[PORT], CryptoPP::ChaCha::IV_LENGTH);
			config["IV"]["TOR PORT"] = to_hex_str(IVs[TOR_PORT], CryptoPP::ChaCha::IV_LENGTH);
			config["IV"]["PUBLIC"] = to_hex_str(IVs[PUBLIC], CryptoPP::ChaCha::IV_LENGTH);
			config["IV"]["PRIVATE"] = to_hex_str(IVs[PRIVATE], CryptoPP::ChaCha::IV_LENGTH);
			config["IV"]["PUBLIC B"] = to_hex_str(IVs[PUBLIC_B], CryptoPP::ChaCha::IV_LENGTH);
			config["IV"]["PRIVATE B"] = to_hex_str(IVs[PRIVATE_B], CryptoPP::ChaCha::IV_LENGTH);
		}
};

// encrypt/decrypt configure.json values in every session
// config_path: the path of configure.json
// keys_path: path of keys.txt
void cipher_config(std::string config_path, std::string keys_path=global_settings.keys)
{
	uint8_t *key = new uint8_t[32];
	get_port_ip_key(key, keys_path); // assign key from file to array

	// encrypt all values in configure
	Configure config = Configure(config_path);
	CryptoPP::ChaCha::Encryption chacha;
	

	// encrypt port
	uint8_t *str_port = new uint8_t[2];
	uint8_t port_len;

	 // convert port to bytearray
	if (config.port > 0xff) {
		str_port[0] = (uint8_t)(config.port >> 8);
		str_port[1] = (uint8_t)config.port;
		port_len = 2;
	} else {
		*str_port = (uint8_t)config.port;
		port_len = 1;
	}
	// encrypt port
	uint8_t *ct = new uint8_t[port_len];
	chacha.SetKeyWithIV(key, 32, config.IVs[config.PORT]); // 256-bit chacha20 encryption key
	chacha.ProcessData(ct, (const CryptoPP::byte *)str_port, port_len);
	config.port = ((uint16_t)ct[0] << 8) | ct[1];
	
	// encrypt/decrypt tor port

	 // convert tor port to bytearray
	if (config.tor_port > 0xff) {
		str_port[0] = (uint8_t)(config.tor_port >> 8);
		str_port[1] = (uint8_t)config.tor_port;
		port_len = 2;
	} else {
		*str_port = (uint8_t)config.tor_port;
		port_len = 1;
	}
	delete[] ct;
	ct = new uint8_t[port_len];


	chacha.SetKeyWithIV(key, 32, config.IVs[config.TOR_PORT]); // 256-bit chacha20 encryption key
	chacha.ProcessData(ct, (const CryptoPP::byte *)str_port, port_len);
	config.tor_port = ((uint16_t)ct[0] << 8) | ct[1];
	delete[] str_port;
	delete[] ct;

	// encrypt/decrypt public ip, all IPs are encrypted byte by byte. the dots aren't encrypted
	ct = new uint8_t[4];
	uint8_t *ip = new uint8_t[4];
	parse_ip(ip, config.public_ip);
	chacha.SetKeyWithIV(key, 32, config.IVs[config.PUBLIC]); // 256-bit chacha20 encryption key
	chacha.ProcessData(&ct[0], &ip[0], 1);
	chacha.ProcessData(&ct[1], &ip[1], 1);
	chacha.ProcessData(&ct[2], &ip[2], 1);
	chacha.ProcessData(&ct[3], &ip[3], 1);
	config.public_ip = std::to_string(ct[0]+0) + "." + std::to_string(ct[1]+0) + "." + std::to_string(ct[2]+0) + "." + std::to_string(ct[3]+0);

	// encrypt/decrypt private ip
	parse_ip(ip, config.private_ip);
	chacha.SetKeyWithIV(key, 32, config.IVs[config.PRIVATE]); // 256-bit chacha20 encryption key
	chacha.ProcessData(&ct[0], &ip[0], 1);
	chacha.ProcessData(&ct[1], &ip[1], 1);
	chacha.ProcessData(&ct[2], &ip[2], 1);
	chacha.ProcessData(&ct[3], &ip[3], 1);
	config.private_ip = std::to_string(ct[0]+0) + "." + std::to_string(ct[1]+0) + "." + std::to_string(ct[2]+0) + "." + std::to_string(ct[3]+0);

	// on other device,

	// encrypt/decrypt public ip B (other device)
	parse_ip(ip, config.public_b_ip);
	chacha.SetKeyWithIV(key, 32, config.IVs[config.PUBLIC_B]); // 256-bit chacha20 encryption key
	chacha.ProcessData(&ct[0], &ip[0], 1);
	chacha.ProcessData(&ct[1], &ip[1], 1);
	chacha.ProcessData(&ct[2], &ip[2], 1);
	chacha.ProcessData(&ct[3], &ip[3], 1);
	config.public_b_ip = std::to_string(ct[0]+0) + "." + std::to_string(ct[1]+0) + "." + std::to_string(ct[2]+0) + "." + std::to_string(ct[3]+0);

	// encrypt/decrypt private ip B (other device)
	parse_ip(ip, config.private_b_ip);
	chacha.SetKeyWithIV(key, 32, config.IVs[config.PRIVATE_B]); // 256-bit chacha20 encryption key
	chacha.ProcessData(&ct[0], &ip[0], 1);
	chacha.ProcessData(&ct[1], &ip[1], 1);
	chacha.ProcessData(&ct[2], &ip[2], 1);
	chacha.ProcessData(&ct[3], &ip[3], 1);
	config.private_b_ip = std::to_string(ct[0]+0) + "." + std::to_string(ct[1]+0) + "." + std::to_string(ct[2]+0) + "." + std::to_string(ct[3]+0);
	
	config.write_values();
	config.write_to_file();
	delete[] key;
	delete[] ct;
}

int main()
{
	cipher_config("./configure.json");
	std::cout << std::endl;
	return 0;
}
