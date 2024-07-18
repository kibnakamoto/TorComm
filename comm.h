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

#include <stdexcept>
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
#include <cryptopp/strciphr.h>

#include "message.h"
#include "errors.h"

// limits of single message sizes
// If a single message is larger, it might just be a DOS attack so ask the user if they want to receive such a large file
// The actual limit is 18,446,744 TB (UINT64_MAX)
enum SIZE_LIMITS {
	MAX_TEXT_SIZE   = 8192,        // 0x00002000  - 2^13: up to 4KB message
	MAX_FILE_SIZE   = 8589934592, // 0x200000000- 2^34: up to 8GB file
    MAX_DELETE_SIZE = 32,          // 0x00000020  - Doesn't need a limit, same size as packet size
};

// if sizes are less than these, no segmentation needed
enum NO_SEGMENTATION_SIZES {
	// NSEG_TEXT_SIZE   = 8192,        // 0x00000400  - 2^14: up to 8KB message    // TEXT SIZE UNNECESARRY
	NSEG_FILE_SIZE   = 268435456,   // 0x10000000  - 2^29: up to 268MB file
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
void get_info(uint8_t *dat, uint64_t &len, uint8_t &type);


/* ECDH
 * When establishing a new secure public channel, only send ecdh data such as public key to the other person
 * and the curve used. Don't send the whole protocol until it's encrypted.
 */

enum DATA_FORMAT {
	TEXT    = 1024,  // 0x0400   - Default text buffer size, while using, it can be different
	_FILE_  = 2048,  // 00x640   - All types of files
	DELETE  = 32,    // 0x0010   - Send which data to delete, 32 because it will shifted by 5
	ECDH_DATA = 512, // 0x0200   - Public key, symmetrical key size, and elliptic curve
};


// set the first 72-bits of data from packet
uint8_t set_info(uint8_t *dat, uint64_t len, uint8_t type);

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
		std::string ip; // get ip of this device
		Blocked blocked;
		std::map<std::string, CryptoPP::ECPPoint *> public_keys; // public keys of peers. ip address is used to access public key
		// inline static uint32_t max_requests = 10; // the total amount of receive requests that can be made before quitting

		public:

		P2P(uint16_t port, Blocked blocked) : listener(boost::asio::ip::tcp::acceptor(io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v6(), port))),
											  resolver(io_context)
		{
			this->blocked = blocked;
			ip = get_ipv6();
			endpoints = resolver.resolve(ip, std::to_string(port)); // get endpoints

			// listen to oncoming connections
    		listener.listen();
		}

		std::string get_ip()
		{
			return ip;
		}

	    using FunctionSocket = std::function<void(boost::asio::ip::tcp::socket&)>;

		// accept connection, their client sends to this server.
		void accept(const FunctionSocket &lambda=nullptr)
		{
        	listener.async_accept([&](boost::system::error_code const& ec, boost::asio::ip::tcp::socket sock) {
				if (!ec) {
					// if ip address blocked, don't add as a client
		            auto remote_endpoint = sock.remote_endpoint();
    		        if (!remote_endpoint.address().is_unspecified() && blocked.is_blocked(remote_endpoint.address().to_v6().to_string())) {
						std::cout << "\nblocked connection";
						sock.close(); // stop socket because it's blocked
					} else {
						if(std::find_if(clients.begin(), clients.end(), [remote_endpoint](const auto &socket)
						   { return remote_endpoint == socket.remote_endpoint();} ) == clients.end()) {
							std::cout << "\nnew connection to " << remote_endpoint;
				    		clients.push_back(std::move(sock));
							if(lambda) {
								lambda(sock);
							}
						}
					}
				    accept(lambda);
				} else {
					std::cout << std::endl << "P2P::accept() error: " << ec.message() << "\n";
					if(log_network_issues) {
						std::fstream file(NETWORK_LOG_FILE, std::ios_base::app);
						file << "\nerror in P2P::accept(): " << ec.message();
						file.close();
					}
				}
        	});
		}

		// accept connection from specific ip only (group-chat)
		void accept(std::vector<std::string> ips) // TODO: keep up to date with working previous accept function
		{
        	listener.async_accept([&](boost::system::error_code const& ec, boost::asio::ip::tcp::socket sock) {
				if (!ec) {
					// if ip address is in ips
		            auto remote_endpoint = sock.remote_endpoint();
					std::string connected_to = remote_endpoint.address().to_v6().to_string();
					if(!remote_endpoint.address().is_unspecified() && std::any_of(ips.begin(), ips.end(),
					   [connected_to](std::string ip) { return ip == connected_to; })) {

						// it's already connected
						if(std::any_of(clients.begin(), clients.end(), [remote_endpoint](const auto &socket)
						   		   { return remote_endpoint == socket.remote_endpoint(); })) {
							std::cout << "\n" << remote_endpoint << " is already connected";
						} else { // not already connected
							std::cout << "\nnew connection to " << remote_endpoint;
				    		clients.push_back(std::move(sock));
						}
					} else {
						std::cout << "\nIp Not in List. Refusing Connection to " << remote_endpoint;
						sock.close();
					}
				    accept(ips); // continue listening
				} else {
					std::cout << std::endl << "P2P::accept(ips) error: " << ec.message() << "\n";
					if(log_network_issues) {
						std::fstream file(NETWORK_LOG_FILE, std::ios_base::app);
						file << "\nerror in P2P::accept(ips): " << ec.message();
						file.close();
					}
				}
        	});
		}

		// connect to their server even if blocked
		// address: the ip address
		// port_: port to connect to
		// lambda: lambda function, called after successful connection if defined
		// reattempt_after_fail: how many times should it try to reconnect after failing
		void connect(std::string address, uint16_t port_, const FunctionSocket &lambda=nullptr, uint32_t reattempt_after_fail = 5)
		{
			auto endpoint_ = resolver.resolve(address, std::to_string(port_));

			if(endpoint_.empty())
			{
				std::cout << "Failed to Resolve Endpoint For " << address << ":" << port_ << std::endl;
				return;
			}
			
			// Attempt to connect
			auto socket = std::make_shared<boost::asio::ip::tcp::socket>(io_context); // start socket
			servers.emplace_back(std::move(*socket));
			async_connect(*socket, endpoint_, [this, address, port_,
											   reattempt_after_fail, socket, lambda](boost::system::error_code ec,
													   						 		 boost::asio::ip::tcp::endpoint) {
				if (ec) {
					std::cout << "Failed Connection " << reattempt_after_fail << " (" << ec.message()
							  << "): Reconnecting in 3 Seconds..." << std::endl;

					// wait 3 seconds
					boost::asio::steady_timer timer(io_context, boost::asio::chrono::seconds(3));
					timer.wait();
					if (reattempt_after_fail > 1) { // call if reattempt wanted
						connect(address, port_, lambda, reattempt_after_fail - 1);
					} else {
					 	std::cout << "Failed Connection: Too Many Attempts, Connection Failed" << std::endl;
					 	servers.pop_back(); // remove last element because there is an error

						if (log_network_issues) {
							std::fstream file(NETWORK_LOG_FILE, std::ios_base::app);
							file << "\nerror in P2P::connect(): " << ec.message() << " - " << get_time();
							file.close();
						}
					}
				} else {
					std::cout << std::endl << "CALLED ASYNC_CONNECT - SUCCESS" << std::endl << std::flush;
					if(lambda) { // if function exists
						lambda(*socket); // call lambda upen successful connection
					}
				}
			});
		}


		// after calling connect
		// send_to: person receiving
		// return: if the other person exists after called find_to_recv with their ip address.
		bool send_two_party_ecdh(boost::asio::ip::tcp::socket &send_to, Cryptography::ProtocolData protocol,
								 Cryptography::Key &key)
		{
			// no compression
			uint16_t xy_len = Cryptography::get_curve_size(protocol.curve);
			uint16_t length = 1U + (xy_len<<1); // 1-byte protocol + public key

			// send genesis so that the reciever knows what to get
			send_genesis(length, (uint16_t)DATA_FORMAT::ECDH_DATA>>5);

			uint8_t *packet = new uint8_t[length];
			packet[0] = (uint8_t)protocol.curve + (uint8_t)protocol.protocol; // Send the whole protocol publicly

			// save public key to packet
			key.public_key.x.Encode(&packet[1], xy_len, CryptoPP::Integer::UNSIGNED);
			key.public_key.y.Encode(&packet[1+xy_len], xy_len, CryptoPP::Integer::UNSIGNED);

			// send keys
			send(send_to, packet, length);

			// receive their keys
			boost::asio::ip::tcp::socket *recv_from = find_to_recv(send_to.local_endpoint().address().to_string());
			if(!recv_from)
				return 0;

			length--;

			if(!(*recv_from).available()) // check if the sender is available
				return 0;
			recv(*recv_from, &packet[0], length); // reuse packet, receive their public key

			// use their keys
			CryptoPP::ECPPoint public_bob = Cryptography::Key::reconstruct_point_from_bytes(packet, xy_len, &packet[xy_len], xy_len);

			public_keys.insert({recv_from->remote_endpoint().address().to_string(), &public_bob});

			auto shared_secret = key.multiply(public_bob);
			uint16_t shared_secret_len = shared_secret.x.MinEncodedSize();
			shared_secret.x.Encode(&packet[0], shared_secret_len, CryptoPP::Integer::UNSIGNED); // add the data to an array (used packet since it's already allocated)
			key.hkdf(packet, shared_secret_len, (uint8_t*)"", 0, (uint8_t*)"", 0);
			delete[] packet;
			return 1;
		}

		// after calling accept
		// recv_from: the sending node
		// errors: CAN ONLY BE NO_PROTOCOL. CHECK IF NO_PROTOCOL
		// return: if the other person exists after called find_to_recv with their ip address.
		bool recv_two_party_ecdh(boost::asio::ip::tcp::socket &recv_from, Cryptography::ProtocolData protocol,
								 Cryptography::Key &key, ERRORS &error)
		{
			// no compression
			uint16_t xy_len = Cryptography::get_curve_size(protocol.curve);
			uint16_t length = 1U + (xy_len<<1); // 1-byte protocol + public key
			uint8_t *packet = new uint8_t[length];
			
			// receive their keys
			if(!recv_from.available())
				return 0;

			recv(recv_from, &packet[0], length); // reuse packet

			// check if protocol number exists
			if(packet[0] >= Cryptography::LAST_CURVE) {
				#if DEBUG_MODE
					throw std::runtime_error("P2P::recv_two_party_ecdh: NO_PROTOCOL error. the protocol given by the sender is not valid.");
				#endif

				if(log_network_issues) {
					std::fstream file(NETWORK_LOG_FILE, std::ios_base::app);
					file << "\nerror in P2P::recv_two_party_ecdh(recv_from, protocol, key, error): protocol number doesn\'t exist";
					file.close();
				}
				error = NO_PROTOCOL; // no protocol found. Cannot establish secure public channel
				// when calling function: make sure to check if error == NO_PROTOCOL
				return 1;
			}

			protocol.init(packet[0]); // re-initialize protocol
			CryptoPP::ECPPoint public_alice = key.reconstruct_point_from_bytes(&packet[1], xy_len, &packet[xy_len+1], xy_len);

			public_keys.insert({recv_from.remote_endpoint().address().to_string(), &public_alice});

			// save public key to packet
			key.public_key.x.Encode(&packet[0], xy_len, CryptoPP::Integer::UNSIGNED);
			key.public_key.y.Encode(&packet[xy_len], xy_len, CryptoPP::Integer::UNSIGNED);

			// Alice sends public key
			boost::asio::ip::tcp::socket *send_to = find_to_send(recv_from.local_endpoint().address().to_string());
			if(!send_to)
				return 0;
			length--;
			send(*send_to, packet, length);

			// produce a shared-secret
			auto shared_secret = key.multiply(public_alice);
			uint16_t shared_secret_len = shared_secret.x.MinEncodedSize();
			shared_secret.x.Encode(&packet[0], shared_secret_len, CryptoPP::Integer::UNSIGNED); // add the data to an array (used packet since it's already allocated)
			key.hkdf(packet, shared_secret_len, (uint8_t*)"", 0, (uint8_t*)"", 0);
			delete[] packet;
			
			return 1;
		}

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
			uint8_t *dat = nullptr;
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
			uint8_t *dat = nullptr;
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

		// same as function above + receiver: find_to_recv(address)
		void recv(boost::asio::ip::tcp::socket &receiver, uint8_t *data, std::unsigned_integral auto &packet_size)
		{
			_recv(receiver, boost::asio::buffer(data, packet_size));
		}

		boost::asio::ip::tcp::socket *recv(std::string data)
		{
			return _recv(boost::asio::buffer(data));
		}

		// same as function above + receiver: find_to_recv(address)
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
		// length: length of dat, if file type is a file, then it's the length of filename
		// type: type of message
		// received_from: the socket which received this data
		// file_path: if data type is a file, save to file
		// all parameters are empty until received_from (including),
		// return: successfully received, false if no one is sending, true if function successfully called
		// RUN this function using another thread, this means there are 3 threads for communiciation, 2 for receiver, 1 for sender.
		bool recv_full(std::string dat, uint64_t &length, DATA_FORMAT &type,
					   boost::asio::ip::tcp::socket *received_from, Cryptography::ProtocolData &protocol,
					   Cryptography::Decipher decipher, auto got_decipher, Cryptography::Verifier verifier, std::string file_path="")
		{
			// first receive genesis packet
			uint8_t type_;
			const uint16_t security_len = protocol.mac_size + protocol.iv_size;
			uint8_t div = (protocol.ct_size/protocol.block_size)-1; // ratio of ciphertext length to plaintext length, subtract 1 because will use operator<< rather than operator* (N << 1 = N * 2)
			uint8_t *iv = new uint8_t[protocol.iv_size];
			uint8_t *data;
			received_from = recv_genesis(length, type_);
			if(received_from == nullptr) {
				return 0; // no one is sending
			}
			type = (DATA_FORMAT)((uint16_t)type_<<5); // converted to uint16 so that the shift doesn't overflow

			/* PADDING OF FILES:
			 * before filename length, add a one byte padding length. When writing to a file, only add up to the length - padding_length
			 */


			// receive full packet
			if(type == DATA_FORMAT::_FILE_) {
				uint8_t *plain;
				uint64_t pt_len;

				// no segmentation needed
				if(length <= NO_SEGMENTATION_SIZES::NSEG_FILE_SIZE) {
					data = new uint8_t[length]; // ciphertext data
					recv(*received_from, data, length); // receive the data
					uint64_t cipher_len = length-security_len;
					pt_len = cipher_len >> div;
					plain = new uint8_t[pt_len];

					// data format: MAC + IV + encrypted(pad-size + padding + filename-length + filename + DATA)
					memcpy(iv, &data[protocol.mac_size], protocol.iv_size); // get iv
					// mac is data[0]-data[protocol.mac_size]

					// decrypt
					decipher.assign_iv(iv);
					decipher.decrypt(&data[security_len], cipher_len, plain, pt_len, data);

					// get file name and padding
					uint16_t file_name_len;
					uint8_t pad_size;
					dat = read_file(plain, file_name_len, pad_size);
					
					// add rest of data to a file
					const uint32_t data_start_index = 3 + pad_size + (uint32_t)file_name_len; // this is the index where the file content start.
					
					length = pt_len-data_start_index; // set length of file

					// verify
					bool verified = verifier.verify(&data[security_len], cipher_len, plain, pt_len, data,
													public_keys.at(received_from->remote_endpoint().address().to_string())); // verified is saved in verifier
					if(verified) { // if correct data, save it
						std::ofstream file(dat);// add the file data to a file
						file.write(reinterpret_cast<char*>(&plain[data_start_index]), length);
						file.close();
					}
				} else { // a large file, needs segmentation
					const uint16_t cipher_len = (type + protocol.block_size)<<div; // ciphertext length per packet
					const uint16_t packet_len = security_len + cipher_len; // length of every packet
					data = new uint8_t[packet_len]; // whole data
					recv(*received_from, data, packet_len); // receive the data

					// data format: MAC + IV + encrypted(pad-size + padding + filename-length + filename + DATA)
					memcpy(iv, &data[protocol.mac_size], protocol.iv_size); // get iv
					// mac can stay in data

					// decrypt
					pt_len = type;
					decipher.assign_iv(iv);
					decipher.decrypt(&data[security_len], cipher_len, plain, pt_len, data);

					bool verified = verifier.verify(&data[security_len], cipher_len, plain, pt_len, data,
													public_keys.at(received_from->remote_endpoint().address().to_string())); // verified is saved in verifier
					if(!verified) {
						delete[] plain;
						delete[] iv;
						delete[] data;
						return 1; // someone was sending so return 1
					}

					// get file name and padding
					uint16_t file_name_len;
					uint8_t pad_size;
					dat = read_file(plain, file_name_len, pad_size);
					
					// add file data to a file
					const uint32_t data_start_index = 3U + pad_size + (uint32_t)file_name_len; // this is the index where the file content start.
					const uint64_t newlen = pt_len - data_start_index; // remove other data.
					std::ofstream file(dat);// add the file data to a file
					file.write(reinterpret_cast<char*>(&plain[data_start_index]), newlen);

					received_size = packet_len; // static thread_local variable

					// process rest of the packets
					while(received_size < length) {
						recv(*received_from, data, packet_len); // receive the data

						// data format: MAC + IV + encrypted(pad-size + padding + filename-length + filename + DATA)
						memcpy(iv, &data[protocol.mac_size], protocol.iv_size); // get iv

						// decrypt
						decipher.assign_iv(iv);
						decipher.decrypt(&data[security_len], packet_len, plain, pt_len, data);
						
						// verify
						verified = verifier.verify(&data[security_len], packet_len, plain, pt_len, data,
												   public_keys.at(received_from->remote_endpoint().address().to_string())); // verified is saved in verifier

						if(!verified)
							break;

						// add rest of data to a file
						file.write(reinterpret_cast<char*>(plain), pt_len);

						received_size+=packet_len;
					}
					file.close();
				}

				delete[] plain;
			} else { // If data is not a file
				data = new uint8_t[length];
				recv(*received_from, data, length);

				// data format: MAC + IV + DATA
				memcpy(iv, &data[protocol.mac_size], protocol.iv_size); // get iv
				
				length -= security_len; // subtract mac and iv from dat size because it's no longer important
				uint64_t pt_len = length >> div; // plaintext length

				// decrypt
				uint8_t *tmp = new uint8_t[pt_len];
				decipher.assign_iv(iv);
				decipher.decrypt(&data[security_len], length, tmp, pt_len, data);
				length = pt_len; // set length of dat

				// remove padding
				uint8_t pad_size = decipher.unpad(tmp, pt_len);
				dat = reinterpret_cast<char*>(tmp);

				// verify
				verifier.verify(&data[security_len], length, tmp, pt_len, data,
								public_keys.at(received_from->remote_endpoint().address().to_string())); // verified is saved in verifier
			}

			delete[] iv;
			delete[] data;

			return 1;

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

		private:
			thread_local static uint64_t received_size; // this is when receiving large file segments


			// prepare file to send, add file-name
			inline void prepare_file(char *data, std::string file_name, uint16_t file_name_len, char padding)
			{
				// FILE PACKET FORMAT:
				// 1-byte padding size + padding + 2-byte length of file-name + file-name + file-contents
				// when sending the genesis packet, make sure that the length contains the 2-byte length of file-name + file-name (file-name-length + 2)
				data[0] = padding;

				// add padding
				memset(&data[1], 0, padding); // Possibly unnecesary

				data[padding+0] = file_name_len >> 8;
				data[padding+1] = file_name_len & 0xff;
				memcpy(&data[padding+2], file_name.c_str(), file_name_len); // add the file name
			}

			// read file, opposite of the prepare_file function, this is to be called after decryption
			inline std::string read_file(uint8_t *data, uint16_t &file_name_len, uint8_t &padding)
			{
				padding = data[0];
				file_name_len = data[padding] << 8;
				file_name_len |= data[padding+1];
				std::string file_name;
				file_name.reserve(file_name_len);
				memcpy(&file_name[0], reinterpret_cast<char*>(&data[padding+2]), file_name_len); // add the file name
				return file_name;
			}

		public:

		// SEND PROTOCOL (TEXT):
		// 1. pad plaintext to the required plaintext size
		// 2. encrypt plaintext
		// 3. send_genesis to send length and type of message (TEXT, _FILE_, etc.)
		// send the packet in one segment. The segmentation will be done by asio tcp
		//

		// NOTE: if data size is larger than the ram can handle, send in segments. It is necesarry for large data.
		// 	This function is for the whole send protocol for a single message.
		// 	data: plaintext data (string or uint8_t*), if file, string file-path (IF type is _FILE_)
		// 	length: length of data
		// 	type: type of message
		// 	got_cipher: cipher.get_cipher();
		// 	verifier: hmac/ecdsa/GCM
		void send_full(std::string dat, DATA_FORMAT type,
					   Cryptography::ProtocolData &protocol,
					   Cryptography::Cipher &cipher, Cryptography::Verifier verifier)
		{
			uint64_t length = dat.length();
			const uint16_t security_len = protocol.mac_size + protocol.iv_size;
			uint8_t div = (protocol.ct_size/protocol.block_size)-1; // ratio of ciphertext length to plaintext length, subtract 1 because will use operator<< rather than operator* (N << 1 = N * 2)

			// data format for text: MAC + IV + DATA
			// data format for file: MAC + IV + PADDING LENGTH + PADDING + file-name length + file-name + DATA

			// if file type, then make sure to segment data before sending in segments. This is because the file can get really large and not fit in ram
			if(type == DATA_FORMAT::_FILE_) {
				// assumes dat is string file path
				static_assert(std::is_same<decltype(dat), std::string>()); // make sure type is correct, otherwise there is a bug

				// calculate length of file-name + file-length variable
				// the file name length is kept in a 2-byte variable, if overfills, it will send the parts of name that fits
				uint8_t *packet;
				uint8_t *iv;
				char *data;
				const size_t file_name_length = dat.length();
				const uint16_t file_name_len = file_name_length > UINT16_MAX ? UINT16_MAX : (uint16_t)file_name_length;
				uint32_t data_start_index = 3U + (uint32_t)file_name_len; // this is the index where the file content start.

				// find pad length
				uint8_t mod = data_start_index%protocol.block_size;
				uint8_t pad_size = protocol.block_size - mod;
				if(mod == 0)
					pad_size += protocol.block_size;
				data_start_index += pad_size;

				// no segmentation needed
				if(length <= NO_SEGMENTATION_SIZES::NSEG_FILE_SIZE) {
					iv = protocol.generate_iv(); // get new iv
					const uint32_t data_len = data_start_index + length; // here, length is smaller or equal to 2^29 so this can be uint32_t
					const uint32_t cipher_len = (data_len + (protocol.block_size - data_len%protocol.block_size))<<div; // ciphertext length
					data = new char[data_len]; // contains plaintext file name, data
					const uint64_t packet_len = security_len + cipher_len;
					packet = new uint8_t[packet_len]; // contains mac, iv ciphertext file name and data
				
					// send genesis packet
					send_genesis(packet_len, (uint16_t)type>>5);

					// copy file-name length (2-byte), file name and the pad-size (1-byte)
					prepare_file(data, dat, file_name_len, pad_size);

					// read file data
					std::ifstream in(dat);
					in.read(&data[data_start_index], length);

					// encrypt
					uint8_t *u8data = reinterpret_cast<uint8_t*>(data);
					cipher.assign_iv(iv);
					cipher.encrypt(u8data, data_len, &packet[security_len], cipher_len);

					// generate MAC
					verifier.generate(&packet[security_len], cipher_len, u8data, data_len);

					// copy mac and iv
					memcpy(packet, verifier.get_mac(), protocol.mac_size);
					memcpy(&packet[protocol.mac_size], iv, protocol.iv_size);

					// send data, tcp will break down the data
					send(packet, packet_len);

				} else { // data requires segmentation:
					const uint16_t cipher_len = (type + (protocol.block_size - type%protocol.block_size))<<div; // ciphertext length per packet
					const uint16_t packet_len = security_len + cipher_len;
					packet = new uint8_t[packet_len]; // contains mac, iv ciphertext file name and data
					data = new char[type]; // plaintext data segment
					iv = new uint8_t[protocol.iv_size];
					CryptoPP::AutoSeededRandomPool rnd;

					// send genesis packet
					send_genesis(packet_len, (uint16_t)type>>5);

					// add file name to the first packet
					prepare_file(data, dat, file_name_len, pad_size);

					std::ifstream in(dat);
					while(in.good()) {
						// read the segment of data from file
						in.read(&data[data_start_index], type-data_start_index);
					    size_t s_size=in.gcount();
						rnd.GenerateBlock(iv, protocol.iv_size); // generate new iv

						// pad
						if(s_size%protocol.block_size != 0)
							memset(&data[s_size], 0, type-s_size); // since allocated size is valid, then the data_size just needs padding of zeros appended

						// encrypt
						uint8_t *u8data = reinterpret_cast<uint8_t*>(data);
						cipher.assign_iv(iv);
						cipher.encrypt(u8data, s_size, &packet[security_len], cipher_len);
	
						// generate HMAC
						verifier.generate(&packet[security_len], cipher_len, u8data, s_size);

						// copy mac and iv
						memcpy(packet, verifier.get_mac(), protocol.mac_size);
						memcpy(&packet[protocol.mac_size], iv, protocol.iv_size);

						// send packet by packet
						send(packet, packet_len);
						
						data_start_index = 0; // at first, needs to be 2 + file_name_len because it's the first packet with data and needs to have file name
					}
				}
				delete[] data;
				delete[] packet;
				delete[] iv;

				return;
			}

			// For text or delete:

			// find length of full data to send:
			uint8_t *packet;
			uint64_t len = (length + (protocol.block_size - length%protocol.block_size))<<div; // ciphertext length
			uint64_t full_len = len+security_len;
			uint8_t *iv = protocol.generate_iv(); // get new iv
			packet = new uint8_t[full_len];

			 // pad data
			if(length%protocol.block_size != 0) {
				dat = cipher.pad(&dat[0], length);
			}

			// encrypt
			cipher.assign_iv(iv);
			cipher.encrypt(reinterpret_cast<uint8_t*>(&dat[0]), length, &packet[security_len], len);

			// generate HMAC
			verifier.generate(&packet[security_len], len, reinterpret_cast<uint8_t*>(&dat[0]), length);

			// copy mac and iv
			memcpy(packet, verifier.get_mac(), protocol.mac_size);
			memcpy(&packet[protocol.mac_size], iv, protocol.iv_size);

			// send genesis packet
			send_genesis(full_len, (uint16_t)type>>5);

			// send data, tcp will break down the data
			send(packet, full_len);

			delete[] iv;
			delete[] packet;
			/*

			// partition data (if required), encrypt and send
			uint8_t *partition;
			uint16_t length_per_pt = (uint16_t)type/(div+1); // get plaintext packet size. E.g. For text aes256 (1024B packet): 1024/(32/16) = 512B plaintext

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

		boost::asio::ip::tcp::socket *find_to_send(std::string ip)
		{
			for(auto &client : clients) {
				std::string address = client.remote_endpoint().address().to_string();
				if(ip == address) {
					return &client;
				}
			}
			return nullptr;
		}

		boost::asio::ip::tcp::socket *find_to_recv(std::string ip)
		{
			for(auto &server : servers) {
				std::string address = server.remote_endpoint().address().to_string();
				if(ip == address) {
					return &server;
				}
			}
			return nullptr;
		}

		private:
			// send to everybody
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

		// receive from everybody
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
