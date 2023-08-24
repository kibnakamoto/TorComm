#include <iostream>
#include <string>
#include <fstream>

#include "keys.h"
#include "settings.h"

#include <openssl/rand.h>

// 1. Generate keys for encrypting ports and IPs
//
// FORMAT:
// PORT_KEY.IP_KEY
// e.g.
// 5403.40.54.120.230
//
// encrypt using ChaCha20 because it is a stream cipher, get PORT_KEY in 2 bytes and IP_KEY in byte.byte.byte.byte format

// generate openssl port key (uint16_t)
uint16_t rand_port_key()
{
	uint8_t key[2];
	RAND_bytes(key, 2);
	return ((uint16_t)key[0] << 8) | key[1];
}

// generate openssl ip key uint8_t.uint8_t.uint8_t.uint8_t
std::string rand_ip_key()
{
	uint8_t key[4];
	RAND_bytes(key, 4);
	std::string str;
	str += std::to_string(key[0]+0);
	str += ".";
	str += std::to_string(key[1]+0);
	str += ".";
	str += std::to_string(key[2]+0);
	str += ".";
	str += std::to_string(key[3]+0);
	return str;
	
}

template<uint16_t bytesize>
std::string gen_key()
{
	uint8_t key[bytesize];
	RAND_bytes(key, bytesize);
	return key;
}

// TODO: before writing to file, make sure to ask user to backup all keys before replacing
// TODO: make sure to decrypt all IPs and ports before replacing file

void new_port_ip_keys()
{
	std::ofstream file;
	std::string ip_key = rand_ip_key();
	uint16_t port = rand_port_key();
	Settings settings = Settings();
	
	file.open(settings.keys, std::ios_base::out);
	file << port << "." << ip_key;
}

static uint8_t port_key[2];
static uint8_t ip_key[4];

void get_port_ip_keys(uint8_t *port_k=port_key, uint8_t *ip_k=ip_key, std::string keys_path=global_settings.keys)
{
	std::ifstream keys_file(keys_path);
	std::string keys;
	std::getline(keys_file, keys);
	size_t keys_dot = keys_dot = keys.find('.');
	uint16_t val = std::stoi(keys.substr(0, keys_dot));

	// assign port_key
	port_k[0] = val >> 8;
	port_k[1] = val & 0xff;
	keys.erase(0, keys_dot + 1);
	
	// assign ip_key
	uint8_t i=0;
	while ((keys_dot = keys.find('.')) != std::string::npos)
	{
		uint8_t byte = std::stoi(keys.substr(0, keys_dot));
		ip_k[i] = byte;

	    keys.erase(0, keys_dot + 1);
		i++;
	}
	ip_k[3] = std::stoi(keys);
}

// encrypt configure.json values in every session
// config_path: the path of configure.json
// keys_path: path of keys.txt
void encrypt_configs(std::string config_path, std::string keys_path=global_settings.keys)
{
	get_port_ip_keys(port_key, ip_key, keys_path);

	// encrypt port
	
}

int main()
{
	encrypt_configs("./configure.sh");
	return 0;
}
