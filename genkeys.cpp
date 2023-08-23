#include <iostream>
#include <string>
#include <fstream>

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

uint16_t rand_port_key()
{
	uint8_t key[2];
	RAND_bytes(key, 2);
	return ((uint16_t)key[0] << 8) | key[1];
}

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

// TODO: before writing to file, make sure to ask user to backup all keys before replacing
// TODO: make sure to decrypt all IPs and ports before replacing file

int main()
{
	std::ofstream file;
	std::string ip_key = rand_ip_key();
	uint16_t port = rand_port_key();
	Settings settings = Settings();
	
	file.open(settings.keys, std::ios_base::out);
	file << port << "." << ip_key;

	return 0;
}
