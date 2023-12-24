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


#ifndef COMM_H
#define COMM_H

#include <stdint.h>
#include <string>
#include <concepts>
#include <cstdlib>

#include <boost/asio/buffer.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio.hpp>

#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>

#include "message.h"
#include "errors.h"

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

// type of Packet template T
template<typename T>
concept Packet_T_Type = requires(T t)
{
	{
		(std::same_as<T, std::string> || 
		 std::same_as<T, uint8_t*>)
	};
};

// type of buffer in send/recv
template<typename T>
concept Boost_Buffer_Type = requires(T t)
{
	{
		(std::same_as<T, boost::asio::mutable_buffers_1> || 
		 std::same_as<T, boost::asio::const_buffers_1>)
	};
};


// For parsing received network packets
// parse packet to get text, images, videos, or delete
// then use Message class to 
static void get_info(uint8_t *dat, uint64_t &len, uint8_t &type);


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

enum DATA_FORMAT {
	TEXT    = 1024,  // 0x0400   - Default text buffer size, while using, it can be different
	IMAGE   = 1504,  // 0x05e0
	VIDEO   = 2048,  // 0x0800
	_FILE_  = 1600,  // 00x640   - Also includes ZIP files.
	DELETE  = 16,    // 0x0010   - send which data to delete
};


// get the data information from data
// dat: bytearray of len and type
// len: length
// type: type of message (TEXT, IMAGE, etc)
// return: length of dat
static uint8_t set_info(uint8_t *dat, uint64_t len, uint8_t type);

// PROTOTYPIC:
// Message structure for the first packet in communciation, First 4 bytes of message is message length, the rest is message, this is only on first message block
// 4 byte msg_len
// 1020 byte default packet size
// template<typename T>
// struct GenesisPacket
// {
// 	uint64_t msg_len;
// 	uint8_t msg_type;
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
		inline static uint32_t max_requests = 10; // the total amount of receive requests that can be made before quitting

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
					if(log_network_issues) {
						std::fstream file(NETWORK_LOG_FILE, std::ios_base::app);
						file << "\nerror in P2P::accept(): " << ec.message();
						file.close();
					}
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
					if(log_network_issues) {
						std::fstream file(NETWORK_LOG_FILE, std::ios_base::app);
						file << "\nerror in P2P::accept(ips): " << ec.message();
						file.close();
					}
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
					if(log_network_issues) {
						std::fstream file(NETWORK_LOG_FILE, std::ios_base::app);
						file << "\nerror in P2P::connect(): " << ec.message();
						file.close();
					}
				}
			});
		}
		#pragma GCC diagnostic pop

		// start the assynchronous connections. All connections are queued up until now
		void start_async()
		{
			io_context.run();
		}

		/*
		 * ALL Receive & Send Methods Require Their Data to be Padded
		 */

		// send network packet to all
		void send(uint8_t *packet, std::unsigned_integral auto length)
		{
			// client sends network packet
			_send(boost::asio::buffer(packet, length));
		}

		// send network packet to all
		void send(std::string msg)
		{
			// client sends network packet
			_send(boost::asio::buffer(msg));
		}

		// send network packet to address
		void send(boost::asio::ip::tcp::socket &sender, uint8_t *packet, std::unsigned_integral auto length)
		{
			// client sends network packet
			_send(sender, boost::asio::buffer(packet, length));
		}

		// send network packet to address
		void send(boost::asio::ip::tcp::socket &sender, std::string msg)
		{
			// client sends network packet
			_send(sender, boost::asio::buffer(msg));
		}

		// send genesis packet
		void send_genesis(uint64_t len, uint8_t type)
		{
			// client sends network packet
			uint8_t *dat;
			uint8_t dat_len = set_info(dat, len, type);
			for(auto &client : clients) {
				boost::asio::async_write(client, boost::asio::buffer(dat, dat_len), [&](boost::system::error_code ec, uint64_t) {
					if (ec) {
						if(log_network_issues) {
							std::fstream file(NETWORK_LOG_FILE, std::ios_base::app);
							file << "\nerror in P2P::send_genesis(len, type): " << ec.message();
							file.close();
						}
					}
				});
			}
			delete[] dat;
		}

		// send genesis packet
		void send_genesis(boost::asio::ip::tcp::socket &sender, uint64_t len, uint8_t type)
		{
			// client sends network packet
			uint8_t *dat;
			uint8_t dat_len = set_info(dat, len, type);
			boost::asio::async_write(sender, boost::asio::buffer(dat, dat_len), [&](boost::system::error_code ec, uint64_t) {
				if (ec) {
					if(log_network_issues) {
						std::fstream file(NETWORK_LOG_FILE, std::ios_base::app);
						file << "\nerror in P2P::send_genesis(address, len, type): " << ec.message();
						file.close();
					}
				}
			});
			delete[] dat;
		}
		
		// receive network packet
		// both these variables rely on recv_genesis() output.
		// data: whole data received
		// packet_size: packet size of the received packet, this is for knowing how much of the array is valid
		// return: who sent the message
		boost::asio::ip::tcp::socket *recv(uint8_t *data, std::unsigned_integral auto &packet_size)
		{
			return _recv(boost::asio::buffer(data, packet_size));
		}

		// same as function above + receiver: find_to_send(address)
		void recv(boost::asio::ip::tcp::socket &receiver, uint8_t *data, std::unsigned_integral auto &packet_size)
		{
			_recv(receiver, boost::asio::buffer(data, packet_size));
		}

		boost::asio::ip::tcp::socket *recv(std::string data)
		{
			return _recv(boost::asio::buffer(data));
		}

		// same as function above + receiver: find_to_send(address)
		void recv(boost::asio::ip::tcp::socket &receiver, std::string data)
		{
			_recv(receiver, boost::asio::buffer(data));
		}

		// RECEIVE PROTOCOL:
		// This is designed to minimize wasting KBs for receiving a small text message. a hello message network packet should be received with a length of 5
		// 1. recv_genesis to get length and protocol-id
		// 2.   recv data of length packet_size determined by protocol id
		// 3. if length > packet_size for the type of data (TEXT, IMAGE, VIDEO, etc.):
		// 4. 	recv(data, packet_size)
		// 5. else:
		// 		recv(data, length)

		// dat: data container to hold received data
		// length: length of dat
		// type: type of message
		// received_from: the socket which received this data
		// all parameters are empty until received_from (including), 
		// return: successfully received, false if no one is sending
		// RUN this function using another thread, this means there are 3 threads for communiciation, 2 for receiver, 1 for sender.
		bool recv_full(uint8_t *dat, uint64_t &length, DATA_FORMAT &type,
					   boost::asio::ip::tcp::socket *received_from, Cryptography::ProtocolData &protocol,
					   Cryptography::Decipher decipher, auto got_decipher, Cryptography::Hmac hmac)
		{
			// first receive genesis packet
			uint8_t type_;
			uint8_t *iv = protocol.generate_iv();
			received_from = recv_genesis(length, type_);
			if(received_from == nullptr) {
				return 0; // no one is sending
			}
			type = (uint16_t)type_<<5; // converted to uint16 so that the shift doesn't overflow

			// receive full packet
			uint8_t *data = new uint8_t[length];
			recv(*received_from, dat, length);

			// data format: MAC + IV + DATA
			memcpy(&hmac.get_mac()[0], dat, protocol.mac_size); // get mac
			memcpy(iv, dat, protocol.iv_size); // get iv
			
			uint64_t pt_len; // plaintext length
			uint16_t security_len = protocol.mac_size + protocol.iv_size;
			length -= security_len; // subtract mac and iv from dat size because it's no longer important

			// decrypt
			decipher.assign_iv(iv);
			decipher.set_key(got_decipher);
			decipher.decrypt(got_decipher, &data[security_len], length, dat, pt_len, 0);
			length = pt_len; // set length of dat

			// verify
			bool verified = hmac.verify(dat, pt_len);

			delete[] iv;
			delete[] data;

			// add to log if user wants network log
			if(log_network_issues) {
				
			}

			return verified;

			/* received data by manually creating the packets
			// receive all data based on ciphertext length
			if(length <= type) { // if single packet message
				uint8_t *ct = new uint8_t[length]; // ciphertext
				recv(*received_from, ct, *(uint16_t*)length);

				uint16_t pt_len;
				decipher.decrypt(got_decipher, ct, length, dat, pt_len, 0);
				dat = decipher.unpad(dat, pt_len); // remove cryptographic padding
				delete[] ct;
			} else {
				uint64_t len = length;
				uint8_t *ct = new uint8_t[type]; // ciphertext
				uint16_t pt_len;
				dat = new uint8_t[length]; // plaintext
				uint64_t segment = 0; // segment of data, which packet is received.

				while(len >= type) { // if there are more packets
					recv(*received_from, ct, *(uint16_t*)type);
					
					decipher.decrypt(got_decipher, ct, type, &dat[segment], pt_len, 1);
					len-=type;
					segment+=pt_len;
				}

				if(len != 0) { // if there is data to read, if data wasn't a multiple of type
					pt_len = length-segment; // the amount of plaintext bytes that can be received
					uint8_t *copy = new uint8_t[pt_len]; // create copy so that the padding can be removed without an overflow.
					memcpy(copy, &dat[segment], pt_len);
					recv(*received_from, ct, *(uint16_t*)len);
					
					decipher.decrypt(got_decipher, ct, len, copy, pt_len, 1);
					&dat[segment] = decipher.unpad(copy, pt_len); // remove cryptographic padding
				}
				delete[] ct;
			}
			*/
			return 1;
		}

		// SEND PROTOCOL:
		// 1. pad plaintext to the required plaintext size
		// 2. encrypt plaintext
		// 3. send_genesis to send length and type of message (TEXT, VIDEO, etc.)
		// 4. if ciphertext length smaller than packet size:
		// 5.		send the packet of message with ciphertext length rather than packet size because there will only be one packet
		// 6. else:
		// 			send all the packets with packet size, sending doesn't need padding for the last packet, receiving does, so the last packet will be received with: length modulo packet size

		// NOTE: if data size is larger than the ram can handle, send in segments. This isn't defined yet. It is necesarry for large data. The main problem is that data would be encrypted in segments which means that every encrypted segment would need it's own IV.
		// 	This function is for the whole send protocol for a single message.
		// 	data: plaintext data (string or uint8_t*)
		// 	length: length of data
		// 	type: type of message
		// 	got_cipher: cipher.get_cipher();
		// 	verifier: hmac/ecdsa, *******ONLY SUPPORTS HMAC FOR NOW*******
		void send_full(Packet_T_Type auto dat, uint64_t length, DATA_FORMAT type,
					   Cryptography::ProtocolData &protocol,
					   Cryptography::Cipher &cipher, auto got_cipher, Cryptography::Hmac verifier)
		{
			uint8_t *data; // ciphertext data

			// data format: MAC + IV + DATA

			// find length of full data to send:
			uint8_t div = (protocol.ct_size/protocol.block_size)-1; // ratio of ciphertext length to plaintext length
			uint16_t length_per_pt = (uint16_t)type/(div+1); // get plaintext packet size. E.g. For text aes256 (1024B packet): 1024/(32/16) = 512B plaintext
			const uint16_t security_len = protocol.mac_size + protocol.iv_size;
			uint64_t len = (length + (protocol.block_size - length%protocol.block_size))<<div; // ciphertext length
			uint64_t full_len = len+security_len;
			uint8_t *iv = protocol.generate_iv(); // get new iv
			data = new uint8_t[full_len];

			// copy plaintext data to data

			// first make sure data is of type uint8_t*
			if constexpr(std::same_as<decltype(dat), std::string>) {
				// if string, then data is probably short enough to be copied to another container without wasting ram
				data = new uint8_t[length];
				memcpy(data, (uint8_t*)dat.c_str(), length);
			} else {
				memcpy(&data[security_len], dat, length); // copy the data
			}

			// encrypt
			cipher.assign_iv(iv);
			cipher.set_key(got_cipher); // set key with iv
			cipher.encrypt(got_cipher, dat, length, &data[security_len], len, 1);

			// generate HMAC
			verifier.generate(dat, length);

			// copy mac and iv
			memcpy(data, verifier.mac, protocol.mac_size);
			memcpy(&data[protocol.mac_size], iv, protocol.iv_size);

			// send genesis packet
			send_genesis(len, (uint16_t)type>>5);

			// send data, tcp will break down the data
			send(data, full_len);

			delete[] iv;
			delete[] data;
			/*

			// partition data (if required), encrypt and send
			uint8_t *partition;

			// if length <= packet size, send as a single packet of size length, else: send as segments with length of packet size (type)
			if(len <= type) { // if only one packet required
				uint8_t *copy = new uint8_t[length];
				memcpy(copy, data, length); // copy data
				partition = cipher.pad(copy, *(uint16_t*)length); // pad data
				// can convert length to uint16_t because if len <= type, then it's smaller than 0xffff

				cipher.encrypt(got_cipher, data, length, partition, len, 1);
				send(partition, len);
			} else {
				partition = new uint8_t[type];
				uint64_t index = 0;
				while(len >= type) { // if ciphertext length >= packet size, encrypt and send partition
					cipher.encrypt(got_cipher, &data[index], length_per_pt, partition, type, 1);

					// send partitioned data
					send(partition, type);

					len-=type;
					index+=length_per_pt;
				}
				

				// send the rest of data by padding
				if(len != 0) { // if there is more data
					uint8_t *copy = new uint8_t[len];
					memcpy(copy, &data[index], len);

					// pad final packet
					if(len%32 != 0) copy = cipher.pad(copy, *(uint16_t*)len);

					// encrypt final packet
					uint64_t final_length = len << div;
					cipher.encrypt(got_cipher, copy, len, partition, final_length, 1);

					// send final packet
					send(partition, final_length);
					delete[] copy;
				}
			}
			delete[] partition;

			// if allocated here as string
			if constexpr(std::same_as<decltype(dat), std::string>) {
				// move data to string
				dat.reserve(length);
				memcpy(dat.c_str(), (const char*)data, length);

				delete[] data; // doesn't delete the pointer given as function parameter
				
			}
			*/
		}



		// receive the first packet of the connected series of packets. E.g. 1MB image's first packet is just a few bytes of data containing protocol number and length
		// length: length of data, this is initialized in the function
		// receive network packet data. This is for learning 
		// packet_size: packet size of the received packet, this is for knowing how much of the array is valid
		// return: who sent the message
		boost::asio::ip::tcp::socket *recv_genesis(uint64_t &len, uint8_t &type)
		{
			uint8_t packet_size = 9;
			uint8_t *dat = new uint8_t[packet_size];
			for(auto &server : servers) {
				len = server.available();
				if(len) { // if there is data to read
					boost::asio::async_read(server, boost::asio::buffer(dat, packet_size), [&](boost::system::error_code ec, 
																						   uint64_t) {
						if (!ec) {
							get_info(dat, len, type);
						} else {
							if(log_network_issues) {
								std::fstream file(NETWORK_LOG_FILE, std::ios_base::app);
								file << "\nerror in P2P::recv_genesis(length, packet_size): " << ec.message();
								file.close();
							}
						}
          			});
					delete[] dat;
					return &server; // return since data is received
				}
			}
			delete[] dat;
			return nullptr; // couldn't send to anybody
		}

		// same as function above + receiver: the socket from find_to_recv(address)
		// this will only receive from the address mentioned
		void recv_genesis(boost::asio::ip::tcp::socket &receiver, uint64_t &len, uint8_t &type)
		{
			uint8_t packet_size = 9;
			uint8_t *dat = new uint8_t[packet_size];
			boost::asio::async_read(receiver, boost::asio::buffer(dat, packet_size), [&](boost::system::error_code ec, 
																				   uint64_t) {
				if (!ec) {
					get_info(dat, len, type);
				} else {
					if(log_network_issues) {
						std::fstream file(NETWORK_LOG_FILE, std::ios_base::app);
						file << "\nerror in P2P::recv(data, length, packet_size): " << ec.message();
						file.close();
					}
				}
          	});
			delete[] dat;
		}

		boost::asio::ip::tcp::socket &find_to_send(std::string ip)
		{
			for(auto &client : clients) {
				std::string address = client.remote_endpoint().address().to_string();
				if(ip == address) {
					return client;
				}
			}
		}

		boost::asio::ip::tcp::socket &find_to_recv(std::string ip)
		{
			for(auto &server : servers) {
				std::string address = server.remote_endpoint().address().to_string();
				if(ip == address) {
					return server;
				}
			}
		}

		private:
			void _send(Boost_Buffer_Type auto packet)
			{
				// client sends network packet
				for(auto &client : clients) {
					boost::asio::async_write(client, packet, [&](boost::system::error_code ec, uint64_t) {
						if (ec && log_network_issues) {
							std::fstream file(NETWORK_LOG_FILE, std::ios_base::app);
							file << "\nerror in P2P::_send(packet): " << ec.message();
							file.close();
						}
					});
				}
			}

			// only send to this address
			void _send(boost::asio::ip::tcp::socket &sender, Boost_Buffer_Type auto packet)
			{
				// send network packet to client
				boost::asio::async_write(sender, packet, [&](boost::system::error_code ec, uint64_t) {
					if (ec && log_network_issues) {
						std::fstream file(NETWORK_LOG_FILE, std::ios_base::app);
						file << "\nerror in P2P::_send(ip, packet): " << ec.message();
						file.close();
					}
				});
			}

		// only receive from this address
		void _recv(boost::asio::ip::tcp::socket &receiver, Boost_Buffer_Type auto data)
		{
			boost::asio::async_read(receiver, data, [&](boost::system::error_code ec, uint64_t) {
				if (ec && log_network_issues) {
					std::fstream file(NETWORK_LOG_FILE, std::ios_base::app);
					file << "\nerror in P2P::recv(address, data, packet_size): " << ec.message();
					file.close();
				}
          	});
		}

		boost::asio::ip::tcp::socket *_recv(Boost_Buffer_Type auto data)
		{
			for(auto &server : servers) {
				size_t tmp = server.available();
				if(tmp) {
					boost::asio::async_read(server, data, [&](boost::system::error_code ec, uint64_t) {
						if(ec && log_network_issues) {
							std::fstream file(NETWORK_LOG_FILE, std::ios_base::app);
							file << "\nerror in P2P::recv(data, packet_size): " << ec.message();
							file.close();
						}
          			});
				return &server;
				}
			}
			return nullptr; // received from no one
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
