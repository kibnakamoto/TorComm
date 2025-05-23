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
  * Description: Networking Communication file.
  */

#include <stdint.h>
#include <fstream>
#include <filesystem>
#include <utility>

#include <boost/system/error_code.hpp>
#include <boost/asio.hpp>
#include <boost/array.hpp>

#include "comm.h"
#include "keys.h"
#include "errors.h"

// socks5 proxy:
// https://github.com/sehe/asio-socks45-client/tree/main
//

// get the first 72-bits of data from packet
void get_info(uint8_t *dat, uint64_t &len, uint8_t &type)
{
	// get length and type
	len=0;
	for(uint8_t i=0;i<8;i++) {
		len <<= 8;
		len |= dat[i];
	}
	type = dat[8];
}

// get the data information from data
// dat: bytearray of len and type
// len: length
// type: type of message (TEXT, IMAGE, etc)
// return: length of dat
// set the first 72-bits of data from packet
uint8_t set_info(uint8_t *dat, uint64_t len, uint8_t type)
{
	// dat = new uint8_t[9];

	// get length and type
    dat[0] = len >> 56;
    dat[1] = len >> 48;
    dat[2] = len >> 40;
    dat[3] = len >> 32;
    dat[4] = len >> 24;
    dat[5] = len >> 16;
    dat[6] = len >> 8;
    dat[7] = len;
	dat[8] = type;
	return 9; // 9 bytes of data
}

// blocked ips
Blocked::Blocked(std::string keys_path, std::string blocked_path)
{
	this->blocked_path = blocked_path;
	this->keys_path = keys_path;
	read();
}

// read data from blocked file
void Blocked::read()
{
	std::ifstream file(blocked_path);
	if(file.peek() == std::ifstream::traits_type::eof()) { // if file is empty
		return;
	}

	// delete data if not empty
	if(!ips.empty()) {
		for(size_t i=0;i<ips.size();i++) {
			delete[] ips[i];
			delete[] ivs[i];
		}
		ips.clear();
		ip_lengths.clear();
		ivs.clear();
	}

	std::string line;
	while(std::getline(file, line)) {
		size_t del = line.find(" ");
		if(del == std::string::npos) {
			continue; // line is corrupt, doesn't have space meaning isn't in the right format (ct iv)
		}
		std::string ip = line.substr(0, del);
		std::string iv = line.substr(del+1, (CryptoPP::AES::BLOCKSIZE<<1));

		// convert hex string to pointer
		uint16_t ip_len = ip.length()>>1;
		uint8_t *ip_ptr = new uint8_t[ip_len];
		uint8_t *iv_ptr = new uint8_t[CryptoPP::AES::BLOCKSIZE];
		hex_str_to(ip, ip_ptr);

		hex_str_to(iv, iv_ptr);
		ips.push_back(ip_ptr);
		ivs.push_back(iv_ptr);
		ip_lengths.push_back(ip_len);
	}
	file.close();
}

// destructor
Blocked::~Blocked()
{
	for(size_t i=0;i<ips.size();i++) {
		delete[] ips[i];
		delete[] ivs[i];
	}
}

// block a new ip
void Blocked::block(std::string ip)
{
	if(is_blocked(ip)) return; // already blocked
	uint16_t blocked_len;
	uint8_t *iv = new uint8_t[CryptoPP::AES::BLOCKSIZE];
	uint8_t *encrypted = Cryptography::encrypt_ip_with_pepper(keys_path, ip, blocked_len, iv);
	std::fstream file(blocked_path, std::ios_base::app);

	if(!std::filesystem::is_empty(blocked_path)) { // if file is not empty
		file << "\n";
	}

	// add to file
	for(int i=0;i<blocked_len;i++) {
		file << std::hex << std::setw(2) << std::setfill('0') << encrypted[i]+0;
	}
	file << " ";
	for(int i=0;i<CryptoPP::AES::BLOCKSIZE;i++) {
		file << std::hex << std::setw(2) << std::setfill('0') << iv[i]+0;
	}

	// add to vectors
	ips.push_back(encrypted);
	ivs.push_back(iv);
	ip_lengths.push_back(blocked_len);
	file.close();
}

// check if ip is blocked
// ip: plaintext
bool Blocked::is_blocked(std::string ip)
{
	auto ip_addr = boost::asio::ip::make_address_v6(ip);
	for(uint16_t i=0;i<ips.size();i++) {
		auto decrypted = boost::asio::ip::make_address_v6(Cryptography::decrypt_ip_with_pepper(keys_path, ips[i], ip_lengths[i], ivs[i]));

		// if decrypted equals ip
		if(decrypted == ip_addr) {
			return true;
		}
	}
	return false;
}

// unblock an ip
// return: if ip was blocked
bool Blocked::unblock(std::string ip)
{
	auto ip_addr = boost::asio::ip::make_address_v6(ip);
	for(uint16_t i=0;i<ips.size();i++) {
		boost::asio::ip::address_v6 decrypted;
		// decrypt ip from ips
		try {
			decrypted = boost::asio::ip::make_address_v6(Cryptography::decrypt_ip_with_pepper(keys_path, ips[i], ip_lengths[i], ivs[i]));
		} catch(CryptoPP::InvalidCiphertext &) {
			// wrong IP address so remove it
			ips.erase(ips.begin()+i);
			ip_lengths.erase(ip_lengths.begin()+i);
			ivs.erase(ivs.begin()+i);
		} catch(boost::wrapexcept<boost::system::system_error> &) {
			// wrong IP address so remove it
			ips.erase(ips.begin()+i);
			ip_lengths.erase(ip_lengths.begin()+i);
			ivs.erase(ivs.begin()+i);
		}

		if(decrypted == ip_addr) {
			// remove ip
			delete[] ips[i];
			delete[] ivs[i];
			ips.erase(ips.begin()+i);
			ip_lengths.erase(ip_lengths.begin()+i);
			ivs.erase(ivs.begin()+i);

			write(); // rewrite file
			return true;
		}
	}
	return false;
}

// rewrite the blocked file based on vectors
void Blocked::write()
{
	// rewrite the file
	std::ofstream file(blocked_path);
	uint16_t ips_size = ips.size();
	for(uint16_t i=0;i<ips_size;i++) {
		file << to_hex_str(ips[i], ip_lengths[i]) << " " << to_hex_str(ivs[i], CryptoPP::AES::BLOCKSIZE);
		if(i != ips_size-1) file << "\n";
	}
	file.close();
}

