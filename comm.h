#ifndef COMM_H
#define COMM_H

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <boost/system/error_code.hpp>
#include <cryptopp/cryptlib.h>
#include <stdint.h>
#include <string>

#include <boost/asio.hpp>
#include <cryptopp/aes.h>

#include "message.h"
#include "errors.h"

// The Buffer sizes are NOT CONSTANT, these numbers are for SEGMENTS OF DATA. E.g. 1 byte text message will be sent as 1 byte, not 1024 bytes
// aes-256 encrypted message block sizes, divide by 2 for msg lengths, encrypted length of aes-256

// This is ciphertext size, not plaintext. All data will be send as ciphertext
// This is counting padding
// They are set to be a multiple of 32msg_type
enum BUFFER_SIZES {
	// 8 byte message length + 1-byte msg type + 519-byte message (plaintext size), ciphertext is double the size
	GENESIS_BUFFER_SIZE = 1056,  // 0x020a   - The first message block for all types
	TEXT_BUFFER_SIZE    = 1024,  // 0x0400   - Default text buffer size, while using, it can be different
	IMAGE_BUFFER_SIZE   = 1504,  // 0x05e0
	FILE_BUFFER_SIZE   =  2048,  // 0x0800
	VIDEO_BUFFER_SIZE   = 2048,  // 0x0800
	DELETE_BUFFER_SIZE  = 0,     // 0x0000
};

// limits of single message sizes
// If a single message is larger, it might just be a DOS attack so ask the user if they want to receive such a large file
// The actual limit is UINT64_MAX: 18,446,744,073,709,551,615
enum SIZE_LIMITS {
	MAX_TEXT_SIZE   = 8192,        // 0x00002000  - 2^13: up to 4KB message
	MAX_IMAGE_SIZE  = 1073741824,  // 0x40000000  - 2^30: up to 512MB image
	MAX_FILE_SIZE   = 4294967296,  // 0x100000000 - 2^32: up to 2GB file
	MAX_VIDEO_SIZE  = 8589934592,  // 0x200000000 - 2^33: up to 4GB video
    MAX_DELETE_SIZE = 0,        // 0x00000000  - Doesn't need a limit
};

// For parsing received network packets
// parse packet to get text, images, videos, or delete
// then use Message class to 
template<typename T=uint8_t*>
class PacketParser
{
	public:
			T data;
			uint16_t error; // error code if type isn't string or uint8_t*

			PacketParser(T packet);

			// get the first 72 bits of data, len and type
			void get72bits(uint64_t &len, uint8_t &type);

			// parser functions, they return the parsed output, seperate the parts of the message
			// len: uninitialized
			// type: uninitialized
			// returns uint8_t* or std::string

			T p_text(uint8_t *packet, uint64_t &len, uint8_t &type);

			T p_image(uint8_t *packet, uint64_t &len, uint8_t &type);

			T p_video(uint8_t *packet, uint64_t &len, uint8_t &type);

			T p_file(uint8_t *packet, uint64_t &len, uint8_t &type);

			T p_delete(uint8_t *packet, uint64_t &len, uint8_t &type);
};



// PROTOTYPIC:
// Message structure for the first packet in communciation, First 4 bytes of message is message length, the rest is message, this is only on first message block
// 4 byte msg_len
// 1020 byte default packet size
// template<typename T>
// struct GenesisPacket
// {
// 	uint64_t msg_len;
// 	uint8_t msg_type; // Message::format
// 	T msg;
// };
// 
// template<typename T>
// struct Packet
// {
// 	T msg;
// };

// blocked ips
class Blocked
{
	public:
		std::vector<uint8_t *> ips; // encrypted
		std::vector<uint8_t> ip_lengths; // length of ips
		std::vector<uint8_t *> ivs; // iv of blocked ips
		std::string keys_path; // path to keys file
		std::string blocked_path; // path to blocked file

		// blocked_path: path to file blocked
		Blocked(std::string keys_path, std::string blocked_path)
		{
			this->blocked_path = blocked_path;
			this->keys_path = keys_path;
			read();
		}

		Blocked() = default;

		// read data from blocked file
		void read()
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
		~Blocked()
		{
			for(size_t i=0;i<ips.size();i++) {
				delete[] ips[i];
				delete[] ivs[i];
			}
		}

		// block a new ip
		void block(std::string ip)
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
		bool is_blocked(std::string ip)
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
		bool unblock(std::string ip)
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
		void write()
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
};

// P2P has Client and Server on all connections
class P2P
{
		boost::asio::io_context io_context;
		std::vector<boost::asio::ip::tcp::socket> clients;
		std::vector<boost::asio::ip::tcp::socket> servers;
		boost::asio::ip::tcp::acceptor listener;
		uint8_t *buffer;
		boost::asio::ip::v6_only ipv6_option{true};
		std::string local_key_path; // keys file
		Blocked blocked;

		P2P(uint16_t port, Blocked blocked) : listener(boost::asio::ip::tcp::acceptor(io_context, {{}, port}, true))
		{
			this->blocked = blocked;
		}

		// listen to oncoming connections
		void listen()
		{
    		listener.listen();
		}

		// accept connection
		void accept()
		{
        	listener.async_accept([&](boost::system::error_code const& ec, boost::asio::ip::tcp::socket sock) {
				if (!ec) {
					sock.set_option(ipv6_option);

					// if ip address blocked, don't add as a client
					if(blocked.is_blocked(sock.remote_endpoint().address().to_string())) {
						sock.close(); // stop socket because it's blocked
					} else {
				    	clients.push_back(std::move(sock));
					}
				    accept();
				}
        	});
		}

		void send(uint8_t type);

		uint8_t *recv();
};
#endif /* COMM_H */
