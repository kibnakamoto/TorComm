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
  * Description: Cryptography file for message security.
  */

#ifndef MESSAGE_H
#define MESSAGE_H

#include <cstdlib>
#include <functional>
#include <string>
#include <concepts>
#include <stdlib.h>
#include <utility>
#include <filesystem>
#include <variant>

#include <boost/asio/buffer.hpp>

#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/integer.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/modes.h>
#include <cryptopp/rijndael.h>
#include <cryptopp/gcm.h>
#include <cryptopp/chacha.h>
#include <cryptopp/filters.h>
#include <cryptopp/pubkey.h>
#include <cryptopp/sha.h>

#include <json/json.h>

#include "settings.h"
#include "keys.h"
#include "errors.h"

// get current time
std::string get_time();

namespace Cryptography
{
	// GLOBAL:
	// cipher suites
	// 	 ECDH for key communication
	// 	 HKDF for key derevation
	enum CommunicationProtocol {
		// use ECDSA for verification
		ECIES_ECDSA_AES256_CBC_SHA256,
		ECIES_ECDSA_AES256_CBC_SHA512,
		ECIES_ECDSA_AES192_CBC_SHA256,
		ECIES_ECDSA_AES192_CBC_SHA512,
		ECIES_ECDSA_AES128_CBC_SHA256,
		ECIES_ECDSA_AES128_CBC_SHA512,

		// use GCM for verification
		ECIES_AES256_GCM_SHA256,
		ECIES_AES256_GCM_SHA512,
		ECIES_AES192_GCM_SHA256,
		ECIES_AES192_GCM_SHA512,
		ECIES_AES128_GCM_SHA256,
		ECIES_AES128_GCM_SHA512,

		// use HMAC for verification
		ECIES_HMAC_AES256_CBC_SHA256,
		ECIES_HMAC_AES256_CBC_SHA512,
		ECIES_HMAC_AES192_CBC_SHA256,
		ECIES_HMAC_AES192_CBC_SHA512,
		ECIES_HMAC_AES128_CBC_SHA256,
		ECIES_HMAC_AES128_CBC_SHA512,
		ECIES_HMAC_AES128_GCM_SHA512,

		ECIES_ECDSA_CHACHA20_SHA256, // ChaCha20 cipher
		ECIES_ECDSA_CHACHA20_SHA512,
		ECIES_HMAC_CHACHA20_SHA256, // HMAC
		ECIES_HMAC_CHACHA20_SHA512,
		LAST // not a value, just for iteration
	};

	const std::string communication_protocols[] {
		"ECIES_ECDSA_AES256_CBC_SHA256",
		"ECIES_ECDSA_AES256_CBC_SHA512",
		"ECIES_ECDSA_AES192_CBC_SHA256",
		"ECIES_ECDSA_AES192_CBC_SHA512",
		"ECIES_ECDSA_AES128_CBC_SHA256",
		"ECIES_ECDSA_AES128_CBC_SHA512",
		"ECIES_AES256_GCM_SHA256",
		"ECIES_AES256_GCM_SHA512",
		"ECIES_AES192_GCM_SHA256",
		"ECIES_AES192_GCM_SHA512",
		"ECIES_AES128_GCM_SHA256",
		"ECIES_AES128_GCM_SHA512",
		"ECIES_HMAC_AES256_CBC_SHA256",
		"ECIES_HMAC_AES256_CBC_SHA512",
		"ECIES_HMAC_AES192_CBC_SHA256",
		"ECIES_HMAC_AES192_CBC_SHA512",
		"ECIES_HMAC_AES128_CBC_SHA256",
		"ECIES_HMAC_AES128_CBC_SHA512",
		"ECIES_ECDSA_CHACHA20_SHA256",
		"ECIES_ECDSA_CHACHA20_SHA512",
		"ECIES_HMAC_CHACHA20_SHA256",
		"ECIES_HMAC_CHACHA20_SHA512"
	};

	// make sure all doesn't exceed one byte
	enum Curves
	{
		SECP256K1, // SECP256K1 + ECIES_ECDSA_AES256_CBC_SHA256 is the communication protocol
		SECP256R1=LAST,
		SECP521R1=LAST*2,
		BRAINPOOL256R1=LAST*3,
		BRAINPOOL512R1=LAST*4,
		LAST_CURVE=LAST*5 // not a value
	};

	// returns the byte size of elliptic curve
	inline uint8_t get_curve_size(Curves curve)
	{
		switch(curve) {
			case SECP256K1:
			case SECP256R1:
			case BRAINPOOL256R1:
				return 32;
			case BRAINPOOL512R1:
				return 64;
			case SECP521R1:
				return 66;
			default:
				return 0;
		}
	}


	enum CipherAlgorithm {
		AES256,
		AES192,
		AES128,
		CHACHA20
	};

	enum CipherMode {
		NO_MODE, // only for chacha
		CBC,
		GCM
	};

	enum HashAlgorithm {
		SHA256,
		SHA512
	};
	
	enum VerificationAlgorithm
	{
		ECDSA,
		HMAC,
		GCM_VERIFICATION // same name as GCM
	};

	// the default values to assign
	// AES uses CBC mode (for performance reasons: https://cryptopp.com/benchmarks.html)
	inline uint8_t default_communication_protocol = (uint8_t)SECP256R1 + ECIES_HMAC_AES256_CBC_SHA256;
	inline uint16_t default_mac_size = 32;
	inline CryptoPP::OID default_elliptic_curve = CryptoPP::ASN1::secp256r1();
	inline VerificationAlgorithm default_verifier = HMAC;
	using default_cipher = CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption; // aes cbc mode
	using default_decipher = CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption; // aes cbc mode
	using default_hash = CryptoPP::SHA256;

	// key_path: path to keys file
	// ct_ip: ciphertext of ip
	// ct_ip_len: length of ct_ip
	// iv: 16-byte iv
	std::string decrypt_ip_with_pepper(std::string key_path, uint8_t *ct_ip, uint16_t ct_ip_len, uint8_t *iv);

	// key_path: path to keys file
	// ip: ip address to encrypt
	// out_len: the new output length. Output is returned
	// iv: 16-byte IV
	uint8_t *encrypt_ip_with_pepper(std::string key_path, std::string ip, uint16_t &out_len, uint8_t *iv);

	// cryptographically secure file move. This means that it will set the file data to zero and write
	// back to file. And then transfer the data to the specified new directory. MUST use for moving keys file
	//
	// src_path: source file path
	// dest_path: destination file path, before calling function, make sure dest_path is empty or doesn't exist
	inline void move_file(std::string src_path, std::string dest_path)
	{
		auto src_file = std::filesystem::path(src_path);

		// read get_keys.o into pointer and set to ones
		if(std::filesystem::exists(src_file)) {
			std::fstream file(src_path, std::ios_base::in | std::ios::binary);
			file.seekg(0, std::ios::beg);
			size_t file_size = std::filesystem::file_size(src_path);
			char *obj = new char[file_size];
			file.read(obj, file_size);

			// create new file with new data
			std::fstream dest_file(dest_path, std::ios::out | std::ios::binary);
			dest_file.write(obj, file_size);
			dest_file.close();

			memset(obj, 0xff, file_size); // set to ones, not zeros, because zeros might not write, because there might be optimizations around writing zeros.
			file.close();
			file.open(src_path, std::fstream::out | std::fstream::trunc);
			file << (const char*)obj; // set all bits
			file.close();
			std::filesystem::remove(src_file); // delete file
			
			delete[] obj;
		}
	}

	// not cryptographically secure since it's not possible
	inline void copy_file(std::string src_path, std::string dest_path)
	{
		auto src_file = std::filesystem::path(src_path);

		// read get_keys.o into pointer and set to ones
		if(std::filesystem::exists(src_file)) {
			std::fstream file(src_path, std::ios_base::in | std::ios::binary);
			file.seekg(0, std::ios::beg);
			size_t file_size = std::filesystem::file_size(src_path);
			char *obj = new char[file_size];
			file.read(obj, file_size);

			// create new file with new data
			std::fstream dest_file(dest_path, std::ios::out | std::ios::binary);
			dest_file.write(obj, file_size);
			dest_file.close();
			delete[] obj;
		}
	}

	// cryptographically secure file deletion, this means to set all file data to one, write back, then delete
	inline void delete_file(std::string path)
	{
		if(std::filesystem::exists(path)) {
			std::fstream file(path, std::ios::ate);
			file.seekg(0, std::ios::beg);
			size_t file_size = std::filesystem::file_size(path);
			char *obj = new char[file_size];
			file.read(obj, file_size);
			memset(obj, 0xff, file_size); // set to ones, not zeros, because zeros might not write, because there might be optimizations around writing zeros.

			file.close();
			file.open(path, std::fstream::out | std::fstream::trunc);
			file << (const char*)obj;
			file.close();
			std::filesystem::remove(path); // delete file

			delete[] obj;
		}
	}

	// initialize general protocol data based on protocol number
	class ProtocolData : public ErrorHandling
	{
		public:
			// hash
			std::variant<CryptoPP::SHA256, CryptoPP::SHA512> hashf;

			HashAlgorithm hash; // hashing algorithm used
			CipherAlgorithm cipher; // cipher used
			CipherMode cipher_mode; // cipher mode
			Curves curve; // Elliptic curve used
			CryptoPP::OID curve_oid;
			VerificationAlgorithm verifier;
			CommunicationProtocol protocol; // not full communication protocol used, doesn't include elliptic curve used
			uint16_t iv_size;
			uint16_t key_size;
			uint16_t mac_size;
			uint16_t ct_size; // size of ciphertext block size

			// block size of cipher. plaintext has to be a multiple of block_size (padded)
			uint16_t block_size;

			ProtocolData() = default;

			ProtocolData(uint8_t protocol_no);

			void init(uint8_t protocol_no);

			ProtocolData(CommunicationProtocol protocol, Curves curve);

			uint8_t *generate_iv();


		private:
			// error handler for hash function not found
			std::function<void()> error_handler_hash_function_not_found=[]() {
				if (!USE_DEFAULT_VALUES) // defined in errors.h
					throw HASHING_ALGORITHM_NOT_FOUND;
				else
					ProtocolData(default_communication_protocol+0);
			};

			// error handler for encryption algorithm not found
			std::function<void()> error_handler_encryption_function_not_found=[]() {
				if (!USE_DEFAULT_VALUES) // defined in errors.h
					throw ENCRYPTION_ALGORITHM_NOT_FOUND;
				else
					ProtocolData(default_communication_protocol+0);
			};

			// error handler for verification algorithm not found
			std::function<void()> error_handler_verifier_function_not_found=[]() {
				if (!USE_DEFAULT_VALUES) // defined in errors.h
					throw VERIFICATION_ALGORITHM_NOT_FOUND;
				else
					ProtocolData(default_communication_protocol+0);
			};

			void init_cipher_data();
	
			// get information about the hashing algorithm used
			// returns hashing algorithm if applicable
			void init_hash_data();

		public:
			// to get cipher: auto cipher = get_cipher();
			std::variant<CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption, // aes cbc mode
						 CryptoPP::GCM<CryptoPP::AES>::Decryption,      // aes gcm mode
						 CryptoPP::ChaCha::Encryption>                  // ChaCha20
						 get_decipher();

			// to get cipher: auto cipher = get_cipher();
			std::variant<CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption, // aes cbc mode
						 CryptoPP::GCM<CryptoPP::AES>::Encryption,      // aes gcm mode
						 CryptoPP::ChaCha::Encryption>                  // ChaCha20
						   get_cipher();

			// to get hash: auto hashf = get_hash();
			std::variant<CryptoPP::SHA256, CryptoPP::SHA512> get_hash();

			// to get hash: auto hashf = get_curve();
			// returns curve OID (Object ID)
			CryptoPP::OID get_curve();
	};

	// initialize key
	class Key : public ErrorHandling
	{
		ProtocolData protocol;

		public:
				CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> group;
				CryptoPP::Integer private_key;
				CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>::Element public_key;
				uint8_t *key=nullptr; // established key

				Key(ProtocolData &protocol);

				~Key();

				// convert public key to uint8_t*
				static void integer_to_bytes(CryptoPP::Integer num, uint8_t *&bytes, uint16_t &bytes_len);

				static CryptoPP::Integer bytes_to_integer(uint8_t *bytes, uint16_t &bytes_len);

				static CryptoPP::ECPPoint reconstruct_point_from_bytes(uint8_t *public_key_x,
																	   uint16_t public_key_x_len,
																	   uint8_t *public_key_y,
																	   uint16_t public_key_y_len);

				// bob's public key is multiplied with alice's private key to generate the ECDH key.
				CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>::Element
				multiply(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>::Element b_public_k);

				// bob's public key is multiplied with alice's private key to generate the ECDH key.
				CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>::Element
				multiply(CryptoPP::Integer priv_key,
						 CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>::Element b_public_k);

				// Hash based key deravation function
				void hkdf(uint8_t * password, uint16_t password_len, uint8_t *salt, uint16_t salt_len, uint8_t *info, uint16_t info_len);
	};

	namespace /* INTERNAL NAMESPACE */
	{
		// for operators in Decryptor for cbc and gcm aes decryption
		template<typename T>
		concept SupportedHashAlgs = requires(T t)
		{
			{
				(std::same_as<T, CryptoPP::SHA256> || 
				 std::same_as<T, CryptoPP::SHA512>)
			};
		};
	} /* END INTERNAL NAMESPACE */


	// encryption
	class Cipher : public ErrorHandling
	{
		ProtocolData protocol;
		uint8_t *key; // key length is protocol.key_size
		uint8_t *iv; // iv length is protocol.iv_size
		CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption op1; // aes cbc mode
		CryptoPP::GCM<CryptoPP::AES>::Encryption op2;      // aes gcm mode
		CryptoPP::ChaCha::Encryption op3;                  // ChaCha20
		std::string gcm_out;
		std::string gcm_tag;
		int8_t selected;

		public:
				Cipher(ProtocolData &protocol, uint8_t *key);

				void assign_iv(uint8_t *iv);
				void assign_key(uint8_t *key);

				// cipher: output of protocol.get_cipher()
				// data: string, or uint8_t ptr, or buffer, etc. Plaintext
				// length: data length, the send packet length. if 1GB image, it would be IMAGE_BUFFER_SIZE, if last packet. has to be padded to be a multiple of protocol.block_size.
				// ct: ciphertext
				// ct_len: ciphertext length
				// mem_allocated: if memory is allocated, don't reallocate
				void encrypt(uint8_t *pt, uint64_t length, uint8_t *ct, uint64_t ct_len)
				{
						switch(selected) {
							case 0:
								{
								op1.SetKeyWithIV(key, protocol.key_size, iv, protocol.iv_size);
								op1.ProcessData(ct, pt, length);
								break;
								}
							case 1:
								{
								op2.SetKeyWithIV(key, protocol.key_size, iv, protocol.iv_size);
 								CryptoPP::AuthenticatedEncryptionFilter filter(op2, new CryptoPP::StringSink(gcm_out), false, protocol.mac_size, "",
																		  	   CryptoPP::StreamTransformationFilter::NO_PADDING);
 								filter.Put(pt, length);
 								filter.MessageEnd();

								memcpy(ct, to_uint8_ptr(gcm_out), ct_len);
								gcm_tag = gcm_out.substr(ct_len, protocol.mac_size);
								break;
								}
							case 2:
								op3.SetKeyWithIV(key, protocol.key_size, iv, protocol.iv_size);
 								op3.ProcessData(ct, pt, length);
								break;
						}
				}

				// if gcm, return mac
				std::string &get_mac_gcm()
				{
					return gcm_tag; // now that there is a tag, in decipher function make another fucntionality like this. and make sure the tag is verified 
				}

				// to convert strings and boost buffers to uint8_t*
				static uint8_t *to_uint8_ptr(boost::asio::const_buffers_1 data)
				{
					return const_cast<uint8_t*>(boost::asio::buffer_cast<const uint8_t*>(data));
				}

				static uint8_t *to_uint8_ptr(boost::asio::mutable_buffers_1 data)
				{
					return boost::asio::buffer_cast<uint8_t*>(data);
				}

				static uint8_t *to_uint8_ptr(std::string &data)
				{
				 	return reinterpret_cast<uint8_t*>(const_cast<char*>(data.c_str())); // will reinterpret_cast cause endianness problems?
				}

				static uint8_t *to_uint8_ptr(char *data)
				{
					return reinterpret_cast<uint8_t*>(data);
				}

				// reminder: length of data is the length of plaintext data to send. Data packet. Not the whole data

				// data: plaintext bytearray. Must be allocated using new uint8_t[length]
				// length: length of data
				// pad_size: pad_size
				// Pads the data from left to right. no need to remove padding, just remove the first zero digits
				char *pad(char *data, std::unsigned_integral auto &length)
				{
				    char *dat;
					int8_t pad_size;
				    std::remove_reference_t<decltype(length)> original_length = length;
					uint8_t mod = length % protocol.block_size;
				    pad_size = protocol.block_size - mod;
					if(mod == 0) // if 32-byte unpadded, then pad_size=0, if zero, than dat[length-1] = pad_size would modify the plaintext
						pad_size += protocol.block_size;
				    length += pad_size;
					std::cout << "\nlen:" << original_length << "\n";
				    dat = new char[length];
				    memcpy(&dat[pad_size], data, original_length); // for left to right padding
					memset(&dat[1], 0, pad_size-1); // pad it to avoid memory errors detected in valgrind
					dat[0] = pad_size;
				    // memcpy(dat, data, original_length);				  // for right to left padding (append to end of message)
					// dat[length-1] = pad_size; // last digit of data is length
				    delete[] data;
				    return dat;
				}
	};

	// Decryption
	class Decipher : public ErrorHandling
	{
		ProtocolData protocol;
		uint8_t *key; // key length is protocol.key_size
		uint8_t *iv; // iv length is protocol.iv_size
		CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec1; // aes cbc mode
		CryptoPP::GCM<CryptoPP::AES>::Decryption dec2;      // aes gcm mode
		CryptoPP::ChaCha::Encryption dec3;                  // ChaCha20
		std::string gcm_tag;
		int8_t selected;
		bool verified_gcm;

		public:

			Decipher(ProtocolData &protocol, uint8_t *key);

			Decipher() = default;

			// cipher: output of protocol.get_decipher()
			// ct: ciphertext
			// ct_len: ciphertext length
			// data: plaintext
			// length: data length, the send packet length. if 1GB image, it would be IMAGE_BUFFER_SIZE, if last packet. has to be padded to be a multiple of protocol.block_size.
			// decrypts data, doesn't remove padding
			void decrypt(uint8_t *ct, uint64_t ct_len, uint8_t *pt, uint64_t length, uint8_t *mac);

			// set key with iv
			void assign_key(uint8_t *key);

			void assign_iv(uint8_t *iv);

			// remove padding
			// the last value of data is pad size to remove
			// keep the pad size from the original length. delete it accordingly
			// to delete:
			//		delete[] (data-pad_size);
			// data: decrypted padded data
			// length: length of padded data
			// return: pad size
			uint8_t unpad(uint8_t *&data, std::unsigned_integral auto &length)
			{
				uint8_t pad_size = data[0];
				length -= pad_size;
			
				// realloc
				uint8_t *new_data = new uint8_t[length];
				memcpy(new_data, &data[pad_size], length);
				delete[] data;
				data = new_data;
			
				return pad_size;
			}

			// if gcm mode, return if it's verified.
			bool is_verified_gcm()
			{
				return verified_gcm;
			}
	};


	// Elliptic Cryptography Digital Signature Algorithm
	class Ecdsa : public ErrorHandling
	{
		ProtocolData protocol;
		Key *key;
		CryptoPP::AutoSeededRandomPool prng;
		std::vector<uint8_t> signature; // only for when signing, when verifying, give the parameter as uint8_t*
		bool verified;

		// initialize signer
		void signer_init(auto signer, uint8_t *msg, uint16_t msg_len);
		
		public:

		Ecdsa() = default;

		Ecdsa& operator=(Cryptography::Ecdsa &&other)
		{
			this->protocol = other.protocol;
			this->key = other.key;
			this->signature = other.signature;
			this->verified = other.verified;
			return *this;
		}

		Ecdsa(ProtocolData &protocol, Key &key);

		// returns signature as a vector
		// msg: message to sign
		// msg_len: length of message to sign
		void sign(uint8_t *msg, uint16_t msg_len);

		std::vector<uint8_t> get_signature()
		{
			return signature;
		}

		bool is_verified()
		{
			return verified;
		}

		// public key is received as bytes. Convert to ECPoint using: Key::reconstruct_point_from_bytes
		// msg: message to verify
		// msg_len: length of msg
		// signature: ECDSA signature
		// signature_len: length of signature
		// public_key: received public key. Not the own public key
		bool verify(uint8_t *msg, uint16_t msg_len, uint8_t *&signature, uint16_t signature_len,
					CryptoPP::ECPPoint public_key);

		// returns the length of out buffer, gets the compressed x value with the 03 starting byte
		template<SupportedHashAlgs HashAlg>
		inline static uint16_t get_compressed(CryptoPP::ECDSA<CryptoPP::ECP, HashAlg> &public_key, uint8_t *out_buffer);

		// public_key: 03 concatinated with x-coordinate of the public key
		// public_key_len: length of public key
		template<SupportedHashAlgs HashAlg>
		inline static CryptoPP::ECDSA<CryptoPP::ECP, HashAlg> get_decompressed(uint8_t *public_key, uint16_t public_key_len);
	};

	class Hmac : public ErrorHandling
	{
		ProtocolData protocol;
		uint8_t *key;
		uint8_t *mac=nullptr; // output mac
		bool verified;

		// generator initializer
		// hmacf: hmac function
		// pt: plaintext
		// pt_len: plaintext length
		// mac_code: Message Authentecation Code unallocated buffer
		void generator_init(auto hmacf, uint8_t *ct, uint64_t ct_len);
		bool verifier_init(auto hmacf, uint8_t *ct, uint64_t len, uint8_t *hmac);

		public:
				Hmac(ProtocolData &protocol, uint8_t *key);

				Hmac() = default;

				~Hmac();

				uint8_t *get_mac();
				bool is_verified();

				// generate the HMAC code
				void generate(uint8_t *ct, uint64_t len);

				bool verify(uint8_t *ct, uint64_t len, uint8_t *hmac);
	};

	class Verifier
	{
		ProtocolData protocol;
		Hmac hmac;
		Ecdsa ecdsa;
		Decipher *decipher;
		bool verified;
		uint8_t *mac; // not allocated here

		public:
				
				// give Cipher object if goal is generation, give decipher object if goal is verification
				// Cipher and decipher object is only required for GCM mode.
				Verifier(ProtocolData &protocol, Key &key, Cipher *cipher=nullptr, Decipher *decipher=nullptr)
				{
					this->protocol = protocol;

					if (protocol.verifier == HMAC) {
						hmac = Hmac(protocol, key.key);
					} else if (protocol.verifier == ECDSA) {
						ecdsa = Ecdsa(protocol, key);
					} else { // GCM
						mac = Cipher::to_uint8_ptr(cipher->get_mac_gcm()); // already generated
						this->decipher = decipher;
						#if DEBUG_MODE
							if(decipher == nullptr) {
								throw std::runtime_error("Verifier::Verifier: DECIPHER NULL error. In GCM mode, decipher object has to be non-nullptr");
							}
						#endif
					}
				}

				void generate(uint8_t *ct=nullptr, uint64_t ct_len=0, uint8_t *pt=nullptr, uint64_t pt_len=0)
				{
					if (protocol.verifier == HMAC) {
						hmac.generate(ct, ct_len); // hmac ciphertext
						mac = hmac.get_mac();
					} else if (protocol.verifier == ECDSA) {
						ecdsa.sign(pt, pt_len); // sign plaintext
						mac = ecdsa.get_signature().data();
					}
					// GCM generation not needed
				}

				// mac: mac can be ecdsa signature or hmac depending on which is used
				void verify(uint8_t *ct=nullptr, uint64_t ct_len=0, uint8_t *pt=nullptr, uint64_t pt_len=0,
							uint8_t *mac=nullptr, CryptoPP::ECPPoint *public_key=nullptr)
				{
					if (protocol.verifier == HMAC) {
						hmac.verify(ct, ct_len, mac);
						verified = hmac.is_verified();
					} else if (protocol.verifier == ECDSA) {
						ecdsa.verify(pt, pt_len, mac, protocol.mac_size, *public_key);
						verified = ecdsa.is_verified();
					} else { // GCM
						verified = decipher->is_verified_gcm();
					} 
				}

				bool is_verified()
				{
					return verified;
				}

				uint8_t *get_mac()
				{
					return mac;
				}
	};

	// TODO: find a way to secure communication protocol by secritizing some aspects of it
}; /* namespace Cryptography */

// TODO: remember to error handle using
// try {
//		 // create object of class
// } catch(ERRORS error) {
//		// handle error code
// }

// To use ProtocolData: Dont forget try catch for initializing them
// protocol = ProtocolData(Secp256r1 + ECIES_HMAC_AES256_CBC_SHA256);

////////////// KEY
// To use Key:
// k = Key(protocol);
// k.multiply(bobs_key)
// key = k.hkdf();

////////////// CIPHER
// To use Cipher:
// c = Cipher(protocol, key, iv);
// auto cipher = c.get_cipher();
// c.set_key(cipher);
// plaintext = to_uint8_ptr(plaintext_with_non_uint8_type);
// if length % protocol.block_size != 0:
// 		c.pad(plaintext, length);
// 	encrypt option 1:
// c.encrypt(cipher, plaintext, length, ciphertext, ciphertext_length);
// delete[] ciphertext;
// encrypt option 2:
// ciphertext = new uint8_t[ciphertext_length]
// c.encrypt(cipher, plaintext, length, ciphertext_length, ciphertext);
// delete[] ciphertext;
// delete[] plaintext;

////////////// DECIPHER
// To use Decipher:
// d = Decipher(protocol, key, iv);
// auto cipher = d.get_cipher();
// d.set_key(cipher);
// d.decrypt(cipher, ciphertext, ciphertext_length, plaintext, length);
// pad_size = d.unpad(plaintext, length);
// delete[] plaintext;
// delete[] ciphertext;
//

#endif /* MESSAGE_H */
