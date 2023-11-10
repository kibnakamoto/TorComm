#ifndef COMM_H
#define COMM_H

#include <boost/asio/write.hpp>
#include <stdint.h>
#include <string>
#include <concepts>

#include <boost/system/error_code.hpp>
#include <boost/asio.hpp>

#include <cryptopp/cryptlib.h>
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
			uint8_t type;

			PacketParser(T packet);

			// get the data information from data
			// len: length
			// type: type of authentication, processed in ProtocolData
			static void get_info(uint8_t *dat, uint64_t &len, uint8_t &type);

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



// ONCE RECEIVED
// Once data is received, then, you have to remove padding, the thought is that the padding will be subtracted from the length of the message, the length is the first 8 bytes of data that is encrypted

// no information is sent publicly, including the protocol used. the protocol used will be established using a puzzle. The puzzle is, considering that both parties (or more) know the secure key, adding the protocol number to the ecdsa signature then send it. Once received, the recipent has to try all possible protocols to come up with the right protocol.
// for the recipent to know which is the correct protocol:
// 	1. first sent network packet in a new communication requires:
// 		* a random byte array that is encrypted is appended to the end of ciphertext/signature (with a public IV). Because the secret key used is known by the required parties, they can try all ciphers and once it gets a match, it will continue using that protocol. It is kind of a brute force method, but no one else can figure out either the key or the protocol used.

/* This is AFTER PARSING the received message
 * Purpose of this class:
 * Creating images, files, GIFs, and videos as files after receiving.
 * Compressing data when saving to sessions/session-id/messages.json.
 * assigning a timestamp to when the message was received
 */ 

// type of Packet template T
template<typename T>
concept Packet_T_Type = requires(T t)
{
	{
		(std::same_as<T, std::string> || 
		 std::same_as<T, uint8_t*>)
	};
};

// For creating network packets to send
// parse packet to set text, images, videos, or delete, once ready 
template<Packet_T_Type T=uint8_t*>
class Packet
{
	public:
			std::string timestamp; // time of message
			T data;
			uint8_t type; // text, images, videos, delete

			Packet(T packet);
			T msg; // plaintext message to receive
			enum format {TEXT, IMAGE, VIDEO, _FILE_, GIF, DELETE};

		// message and time (optional)
		Packet(T message, std::string tm, Settings settings);

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
		Blocked(std::string keys_path, std::string blocked_path);

		Blocked() = default;

		// read data from blocked file
		void read();

		// destructor
		~Blocked();
		

		// block a new ip
		void block(std::string ip);

		// check if ip is blocked
		// ip: plaintext
		bool is_blocked(std::string ip);

		// unblock an ip
		// return: if ip was blocked
		bool unblock(std::string ip);

		// rewrite the blocked file based on vectors
		void write();
};

// universal genesis packet:
// struct GenesisPacket
// {
// 	uint64_t length;
// 	uint8_t type; // type is TEXT, IMAGE, VIDEO, etc. Cryptography protocol is selected on first connection, not every message has new protocol
// };

// P2P has Client and Server on all connections
class P2P
{
		boost::asio::io_context io_context;
		std::vector<boost::asio::ip::tcp::socket> clients;
		std::vector<boost::asio::ip::tcp::socket> servers;
		boost::asio::ip::tcp::acceptor listener;
		boost::asio::ip::tcp::resolver resolver;
		boost::asio::ip::tcp::resolver::results_type endpoints;
		std::string ip; // get ipv6 of this device
		uint8_t *buffer;
		boost::asio::ip::v6_only ipv6_option{true};
		std::string local_key_path; // keys file
		Blocked blocked;

		P2P(uint16_t port, Blocked blocked) : listener(boost::asio::ip::tcp::acceptor(io_context, {{}, port}, true)),
											  resolver(io_context)
		{
			this->blocked = blocked;
			ip = get_ipv6();
			endpoints = resolver.resolve(ip, std::to_string(port)); // get endpoints

			// listen to oncoming connections
    		listener.listen();
		}

		// accept connection, their client sends to this server.
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
				} else {
					std::fstream file(NETWORK_LOG_FILE, std::ios_base::app);
					file << "\nerror in P2P::accept(): " << ec.message();
					file.close();
				}
        	});
		}

		// accept connection from specific ip only
		void accept(std::vector<std::string> ips)
		{
        	listener.async_accept([&](boost::system::error_code const& ec, boost::asio::ip::tcp::socket sock) {
				if (!ec) {
					std::string sock_ip = sock.remote_endpoint().address().to_string();

					// if ip matches any ips in ips
					if(std::any_of(ips.begin(), ips.end(), [sock_ip](std::string ip) {return ip == sock_ip;})) {
							sock.set_option(ipv6_option);

							// can connect even if blocked
				    		clients.push_back(std::move(sock));
					} else {
						sock.close();
					}
				} else {
					std::fstream file(NETWORK_LOG_FILE, std::ios_base::app);
					file << "\nerror in P2P::accept(ips): " << ec.message();
					file.close();
				}
        	});
		}

		// connect to their server even if blocked
		#pragma GCC diagnostic push
		#pragma GCC diagnostic ignored "-Wunused-parameter"
		void connect()
		{
			auto &socket = servers.emplace_back(io_context); // start socket
			boost::asio::async_connect(socket, endpoints, [this](boost::system::error_code ec, boost::asio::ip::tcp::endpoint endpoint) {
				if (ec) {
					servers.pop_back(); // remove last element because there is an error
					std::fstream file(NETWORK_LOG_FILE, std::ios_base::app);
					file << "\nerror in P2P::connect(): " << ec.message();
					file.close();
				}
			});
		}
		#pragma GCC diagnostic pop

		// start the assynchronous connections. All connections are queued up until now
		void start_async()
		{
			io_context.run();
		}

		// send network packet
		void send(uint8_t *packet, BUFFER_SIZES length)
		{
			// client sends network packet
			_send(boost::asio::buffer(packet, length));
		}

		// send network packet
		void send(std::string msg)
		{
			// client sends network packet
			_send(boost::asio::buffer(msg));
		}
		
		// receive network packet
		// both these variables rely on recv_genesis() output.
		// data: whole data received
		// packet_size: packet size of the received packet, this is for knowing how much of the array is valid
		// return: who sent the message
		std::string recv(uint8_t *data, uint16_t &packet_size)
		{
			for(auto &server : servers) {
				size_t tmp = server.available();
				if(tmp) {
					boost::asio::async_read(server, boost::asio::buffer(data, packet_size), [&](boost::system::error_code ec, 
																						   uint64_t) {
						if (ec) {
							std::fstream file(NETWORK_LOG_FILE, std::ios_base::app);
							file << "\nerror in P2P::recv(data, length, packet_size): " << ec.message();
							file.close();
						}
          			});
					return server.remote_endpoint().address().to_string();
				}
			}
		}

		// same as function above + address: IP address of sender
		std::string recv(std::string address, uint8_t *data, uint16_t &packet_size)
		{
			for(auto &server : servers) {
				std::string ip = server.remote_endpoint().address().to_string();
				if(ip == address) {
					boost::asio::async_read(server, boost::asio::buffer(data, packet_size), [&](boost::system::error_code ec, 
																						   uint64_t) {
						if (ec) {
							std::fstream file(NETWORK_LOG_FILE, std::ios_base::app);
							file << "\nerror in P2P::recv(data, length, packet_size): " << ec.message();
							file.close();
						}
          			});
					return ip;
				}
			}
		}

		// RECEIVE PROTOCOL:
		// This is designed to minimize wasting KBs for receiving a small text message. a hello message network packet should be received with a length of 5
		// 1. recv_genesis to get length and protocol-id
		// 2.   recv data of length packet_size determined by protocol id
		// 3. if length > packet_size for the type of data (TEXT, IMAGE, VIDEO, etc.):
		// 4. 	recv(data, packet_size)
		// 5. else:
		// 		recv(data, length)

		// SEND PROTOCOL:
		// 1. send_genesis

		// receive the first packet of the connected series of packets. E.g. 1MB image's first packet is just a few bytes of data containing protocol number and length
		// length: length of data, this is initialized in the function
		// receive network packet data. This is for learning 
		// packet_size: packet size of the received packet, this is for knowing how much of the array is valid
		// return: who sent the message
		std::string recv_genesis(uint64_t &len, uint8_t &type)
		{
			uint8_t packet_size = 9; // TODO: implement correctly
			uint8_t *dat = new uint8_t[packet_size];
			for(auto &server : servers) {
				len = server.available();
				if(len) { // if there is data to read
					boost::asio::async_read(server, boost::asio::buffer(dat, packet_size), [&](boost::system::error_code ec, 
																						   uint64_t) {
						if (!ec) {
							PacketParser<uint8_t*>::get_info(dat, len, type);
						} else {
							std::fstream file(NETWORK_LOG_FILE, std::ios_base::app);
							file << "\nerror in P2P::recv(data, length, packet_size): " << ec.message();
							file.close();
						}
          			});
					return server.remote_endpoint().address().to_string(); // return since data is received
				}
			}
			delete[] dat;
		}

		// same as function above + address: IP address of the sender
		// this will only receive from the address mentioned
		std::string recv_genesis(std::string address, uint64_t &len, uint8_t &type)
		{
			uint8_t packet_size = 9; // TODO: implement correctly
			uint8_t *dat = new uint8_t[packet_size];
			for(auto &server : servers) {
				std::string ip = server.remote_endpoint().address().to_string();
				if(ip == address) {
					boost::asio::async_read(server, boost::asio::buffer(dat, packet_size), [&](boost::system::error_code ec, 
																						   uint64_t) {
						if (!ec) {
							PacketParser<uint8_t*>::get_info(dat, len, type);
						} else {
							std::fstream file(NETWORK_LOG_FILE, std::ios_base::app);
							file << "\nerror in P2P::recv(data, length, packet_size): " << ec.message();
							file.close();
						}
          			});
					return ip; // return since data is received
				}
			}
			delete[] dat;
		}

		private:
			void _send(boost::asio::mutable_buffers_1 packet)
			{
				// client sends network packet
				for(auto &client : clients) {
					boost::asio::async_write(client, packet, [&](boost::system::error_code ec, uint64_t) {
						if (ec) {
							std::fstream file(NETWORK_LOG_FILE, std::ios_base::app);
							file << "\nerror in P2P::recv(data, length, packet_size): " << ec.message();
							file.close();
						}
						});
				}
			}

			void _send(boost::asio::const_buffers_1 packet)
			{
				// client sends network packet
				for(auto &client : clients) {
					boost::asio::async_write(client, packet, [&](boost::system::error_code ec, uint64_t) {
						if (ec) {
							std::fstream file(NETWORK_LOG_FILE, std::ios_base::app);
							file << "\nerror in P2P::recv(data, length, packet_size): " << ec.message();
							file.close();
						}
					});
				}
			}
};

// TODO: implement a higher level session that uses the P2P class above with cryptography to secure each communication channel. It should also use things give IDs for who send a message
//		// exchange keys with one peer and create a secure communication channel
//		// key: initialized key
//		// protocol: initialized protocol
//		void exchange_keys(Cryptography::Key &key, Cryptography::ProtocolData &protocol);
//
//		// TODO: implement
//		// exchange keys with multiple peers and create a secure communication channel
//		// key: initialized key
//		// protocol: initialized protocol
//		void exchange_keys_all(Cryptography::Key &key, Cryptography::ProtocolData &protocol);

#endif /* COMM_H */
