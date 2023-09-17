#ifndef COMM_H
#define COMM_H

#include <boost/asio/buffer.hpp>
#include <stdint.h>
#include <string>

#include <boost/asio.hpp>

#include "message.h"

// The Buffer sizes are NOT CONSTANT, these numbers are for SEGMENTS OF DATA. E.g. 1 byte text message will be sent as 1 byte, not 1024 bytes
// aes-256 encrypted message block sizes, divide by 2 for msg lengths, encrypted length of aes-256

// This is ciphertext size, not plaintext. All data will be send as ciphertext
// This is counting padding
// They are set to be a multiple of 32
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

// parse packet to get text, images, videos, or delete
// then use Message class to 
template<typename T=uint8_t*>
class PacketParser
{
	public:
			T data;
			uint8_t error;

			PacketParser(T packet);

			// get the first 72 bits of data, len and type
			void get72bits(uint64_t &len, uint8_t &type);

			// parser functions, they return the parsed output, seperate the parts of the message
			// len: uninitialized
			// type: uninitialized
			// returns uint8_t* or std::string

			template<auto R>
			auto p_text(uint8_t *packet, uint64_t &len, uint8_t &type) -> decltype(R);

			template<auto R>
			auto p_image(uint8_t *packet, uint64_t &len, uint8_t &type) -> decltype(R);

			template<auto R>
			auto p_video(uint8_t *packet, uint64_t &len, uint8_t &type) -> decltype(R);

			template<auto R>
			auto p_file(uint8_t *packet, uint64_t &len, uint8_t &type) -> decltype(R);

			template<auto R>
			auto p_delete(uint8_t *packet, uint64_t &len, uint8_t &type) -> decltype(R);
};

// Message structure for the first packet in communciation, First 4 bytes of message is message length, the rest is message, this is only on first message block
// 4 byte msg_len
// 1020 byte default packet size
template<typename T>
struct GenesisPacket
{
	uint64_t msg_len;
	uint8_t msg_type; // Message::format
	T msg;
};

template<typename T>
struct Packet
{
	T msg;
};


// two peer communication
namespace two_parties
{
	// define single client, this is for non-groupchats
	class Client
	{
		Client();
		~Client();
	};

	// define single server, this is for non-groupchats
	class Server
	{
		Server();
		~Server();
	};

	class P2P
	{
		
	};
}; /* namespace two_parties */

// Client can connect to multiple servers
class Client
{
	
};

// Server can have multiple clients
class Server
{
	public:
			uint64_t buffer_size;
			boost::asio::socket_base::receive_buffer_size buff_size_recv;
			boost::asio::socket_base::send_buffer_size buff_size_send;
			boost::asio::io_context io_service();
			//boost::asio::ip::tcp::socket sock;
			uint8_t *buffer;
			std::string ip;
			std::vector<Client> clients;

			Server(std::string ipv6, uint64_t buff_size)
			{
				// set buffer size
				buffer_size = buff_size;
				buffer = new uint8_t[buffer_size];
				ip = ipv6;
				//sock = boost::asio::ip::tcp::socket(io_service);

				//// only ipv6 supported
				//boost::asio::ip::v6_only option_v6(true);
				//sock.set_option(option_v6);

				//boost::asio::buffer(buffer, msg_len);
			}

			~Server();
			
};

// P2P has Client and Server on all connections
class P2P
{

};
#endif /* COMM_H */
