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

#include <jsoncpp/json/json.h>

#include "settings.h"
#include "keys.h"
#include "errors.h"

// get current time
std::string get_time();

namespace Cryptography
{
	// GLOBAL:
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
		ECIES_ECDSA_AES256_GCM_SHA256,
		ECIES_ECDSA_AES256_GCM_SHA512,
		ECIES_ECDSA_AES192_GCM_SHA256,
		ECIES_ECDSA_AES192_GCM_SHA512,
		ECIES_ECDSA_AES128_GCM_SHA256,
		ECIES_ECDSA_AES128_GCM_SHA512,

		// use HMAC for verification (preferred)
		ECIES_HMAC_AES256_CBC_SHA256,
		ECIES_HMAC_AES256_CBC_SHA512,
		ECIES_HMAC_AES192_CBC_SHA256,
		ECIES_HMAC_AES192_CBC_SHA512,
		ECIES_HMAC_AES128_CBC_SHA256,
		ECIES_HMAC_AES128_CBC_SHA512,
		ECIES_HMAC_AES256_GCM_SHA256,
		ECIES_HMAC_AES256_GCM_SHA512,
		ECIES_HMAC_AES192_GCM_SHA256,
		ECIES_HMAC_AES192_GCM_SHA512,
		ECIES_HMAC_AES128_GCM_SHA256,
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
		"ECIES_ECDSA_AES256_GCM_SHA256",
		"ECIES_ECDSA_AES256_GCM_SHA512",
		"ECIES_ECDSA_AES192_GCM_SHA256",
		"ECIES_ECDSA_AES192_GCM_SHA512",
		"ECIES_ECDSA_AES128_GCM_SHA256",
		"ECIES_ECDSA_AES128_GCM_SHA512",
		"ECIES_HMAC_AES256_CBC_SHA256",
		"ECIES_HMAC_AES256_CBC_SHA512",
		"ECIES_HMAC_AES192_CBC_SHA256",
		"ECIES_HMAC_AES192_CBC_SHA512",
		"ECIES_HMAC_AES128_CBC_SHA256",
		"ECIES_HMAC_AES128_CBC_SHA512",
		"ECIES_HMAC_AES256_GCM_SHA256",
		"ECIES_HMAC_AES256_GCM_SHA512",
		"ECIES_HMAC_AES192_GCM_SHA256",
		"ECIES_HMAC_AES192_GCM_SHA512",
		"ECIES_HMAC_AES128_GCM_SHA256",
		"ECIES_HMAC_AES128_GCM_SHA512",
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
	};

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
		HMAC
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
	inline std::string decrypt_ip_with_pepper(std::string key_path, uint8_t *ct_ip, uint16_t ct_ip_len, uint8_t *iv)
	{
		std::string ip;
		LocalKeys local_key(key_path); // get local key parameters like key and length
		
		CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decipherf;
		decipherf.SetKeyWithIV(local_key.keys, local_key.key_len, iv, CryptoPP::AES::BLOCKSIZE);
 		CryptoPP::StreamTransformationFilter filter(decipherf, new CryptoPP::StringSink(ip), CryptoPP::StreamTransformationFilter::NO_PADDING);
 		filter.Put(ct_ip, ct_ip_len>>1);
 		filter.MessageEnd();
	
		// remove padding and pepper
		// ip[0] is pad size
		ip = ip.erase(0, ip[0]+local_key.pepper_len);
		
		return ip;
	}

	// key_path: path to keys file
	// ip: ip address to encrypt
	// out_len: the new output length. Output is returned
	// iv: 16-byte IV
	inline uint8_t *encrypt_ip_with_pepper(std::string key_path, std::string ip, uint16_t &out_len, uint8_t *iv)
	{
		LocalKeys local_key(key_path); // get local key parameters like key and length
		uint16_t ip_len = ip.length();
		uint16_t new_len = local_key.pepper_len+ip_len;

		// pad ip + pepper
		uint8_t pad_size;
		uint8_t mod = new_len % 16;
    	pad_size = 16 - mod;
		if(mod == 0) // if 32-byte unpadded, then pad_size=0, if zero, than dat[length-1] = pad_size would modify the plaintext
			pad_size += 16;
    	new_len += pad_size;
    	uint8_t *in = new uint8_t[new_len];
		memset(in, 0, pad_size); // pad
    	memcpy(&in[pad_size], local_key.get_pepper(), local_key.pepper_len); // add pepper
    	memcpy(&in[pad_size+local_key.pepper_len], ip.c_str(), ip_len); // add ip
		in[0] = pad_size; // first byte of data is length
		out_len = new_len<<1; // ct len is double pt len
		
		// generate IV
		CryptoPP::AutoSeededRandomPool rng;
		rng.GenerateBlock(iv, CryptoPP::AES::BLOCKSIZE); // 16-byte IV

		// encrypt using AES-256-CBC
		uint8_t *out = new uint8_t[out_len];
		CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption cipherf;
		cipherf.SetKeyWithIV(local_key.keys, local_key.key_len, iv, CryptoPP::AES::BLOCKSIZE);
 		CryptoPP::StreamTransformationFilter filter(cipherf, new CryptoPP::ArraySink(out, out_len), CryptoPP::StreamTransformationFilter::NO_PADDING);
 		filter.Put(in, out_len); // TODO: WHY AND HOW IS IT OUT_LEN? IT SHOULD BE NEW_LEN BUT THAT ONLY USES HALF OF OUT. HOW?
 		filter.MessageEnd();
		delete[] in;
		return out;
	}

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
			std::fstream file(src_path, std::ios::ate);
			file.seekg(0, std::ios::beg);
			size_t file_size = std::filesystem::file_size(src_path);
			char *obj = new char[file_size];
			file.read(obj, file_size);

			// create new file with new data
			std::fstream dest_file(dest_path, std::ios::out);
			dest_file << obj;
			dest_file.close();

			memset(obj, 0xff, file_size); // set to ones, not zeros, because zeros might not write, because there might be optimizations around writing zeros.
			file.close();
			file.open(src_path, std::fstream::out | std::fstream::trunc);
			file << (const char*)obj; // set all bits
			file.close();
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

			// encrypt
			std::variant<CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption, // aes cbc mode
						   CryptoPP::GCM<CryptoPP::AES>::Encryption,      // aes gcm mode
						   CryptoPP::ChaCha::Encryption>  cipherf;         // ChaCha20

			// decrypt
			std::variant<CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption, // aes cbc mode
						   CryptoPP::GCM<CryptoPP::AES>::Decryption,      // aes gcm mode
						   CryptoPP::ChaCha::Encryption>                  // ChaCha20
						   decipherf;

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
			
			// for efficient custom error checking
			ERRORS error_code = NO_ERROR;

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
				uint8_t *key; // established key

				Key(ProtocolData &protocol);

				~Key();

				// convert public key to uint8_t*
				static void integer_to_bytes(CryptoPP::Integer num, uint8_t *&bytes, uint16_t &bytes_len);

				static CryptoPP::Integer bytes_to_integer(uint8_t *&bytes, uint16_t &bytes_len);

				inline static CryptoPP::ECPPoint reconstruct_point_from_bytes(uint8_t *public_key_x,
																			  uint16_t public_key_x_len,
																			  uint8_t *public_key_y,
																			  uint16_t public_key_y_len);

				// bob's public key is multiplied with alice's to generate the ECDH key.
				inline CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>::Element
				multiply(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>::Element b_public_k);

				// bob's public key is multiplied with alice's to generate the ECDH key.
				inline CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>::Element
				multiply(CryptoPP::Integer priv_key,
						 CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>::Element b_public_k);

				// Hash based key deravation function
				void hkdf(uint8_t *salt, uint16_t salt_len);
	};

	namespace /* INTERNAL NAMESPACE */
	{
		// for operators in Encryptor for cbc and gcm aes encryption
		template<typename T>
		concept AesEncryptorCBC_GMC = requires(T t)
		{
			{
				(std::same_as<T, CryptoPP::GCM<CryptoPP::AES>::Encryption> || 
				 std::same_as<T, CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption>)
			};
		};

		// for operators in Decryptor for cbc and gcm aes decryption
		template<typename T>
		concept AesDecryptorCBC_GMC = requires(T t)
		{
			{
				(std::same_as<T, CryptoPP::GCM<CryptoPP::AES>::Decryption> || 
				 std::same_as<T, CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption>)
			};
		};

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

		struct Encryptor
		{
			uint8_t *plaintext;
			uint8_t *ciphertext;
			uint16_t plaintext_length;
			uint16_t ciphertext_length;
			bool init=false;

			//void operator()(CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption &enc)
			void operator()(AesEncryptorCBC_GMC auto &enc); // added the requirement of AesEncryptor because the same function required for 2 types

			// void operator()(CryptoPP::GCM<CryptoPP::AES>::Encryption &enc) // same function definition above if concept doesn't work

			void operator()(CryptoPP::ChaCha::Encryption &enc);
		};
		Encryptor encryptor = Encryptor();

		public:
				Cipher(ProtocolData &protocol, uint8_t *key, uint8_t *iv);

				// set key with iv
				void set_key(auto cipher);

				void assign_iv(uint8_t *iv);
				void assign_key(uint8_t *key);

				// cipher: output of protocol.get_cipher()
				// data: string, or uint8_t ptr, or buffer, etc. Plaintext
				// length: data length, the send packet length. if 1GB image, it would be IMAGE_BUFFER_SIZE, if last packet. has to be padded to be a multiple of protocol.block_size.
				// ct: ciphertext
				// ct_len: ciphertext length
				// mem_allocated: if memory is allocated, don't reallocate
				void encrypt(auto &data, uint16_t length, uint8_t *&ct, uint16_t &ct_len, bool &is_ct_allocated);

				// to convert strings and boost buffers to uint8_t*
				static constexpr uint8_t *to_uint8_ptr(auto data);

				// reminder: length of data is the length of plaintext data to send. Data packet. Not the whole data

				// data: plaintext bytearray. Must be allocated using new uint8_t[length]
				// length: length of data
				// pad_size: pad_size
				// Pads the data from left to right. no need to remove padding, just remove the first zero digits
				uint8_t *pad(uint8_t *data, uint16_t &length);
	};

	// Decryption
	class Decipher : public ErrorHandling
	{
		ProtocolData protocol;
		uint8_t *key; // key length is protocol.key_size
		uint8_t *iv; // iv length is protocol.iv_size
		
		struct Decryptor
		{
			uint8_t *plaintext;
			uint8_t *ciphertext;
			uint16_t plaintext_length;
			uint16_t ciphertext_length;
			bool init = false; // is memory allocated

			// check the encryption types
			void operator()(AesDecryptorCBC_GMC auto &dec);

			void operator()(CryptoPP::ChaCha::Encryption &dec);
		};
		Decryptor decryptor = Decryptor();

		public:

			Decipher(ProtocolData &protocol, uint8_t *key, uint8_t *iv);

			// cipher: output of protocol.get_decipher()
			// ct: ciphertext
			// ct_len: ciphertext length
			// data: plaintext
			// length: data length, the send packet length. if 1GB image, it would be IMAGE_BUFFER_SIZE, if last packet. has to be padded to be a multiple of protocol.block_size.
			// decrypts data, doesn't remove padding
			void decrypt(auto &ct, uint16_t ct_len, uint8_t *&pt, uint16_t &length, bool &is_pt_allocated);
			
			// set key with iv
			void set_key(auto cipher);

			// set key with iv
			inline void assign_key(uint8_t *key);

			inline void assign_iv(uint8_t *iv);

			// remove padding
			// the last value of data is pad size to remove
			// keep the pad size from the original length. delete it accordingly
			// to delete:
			//		delete[] (data-pad_size);
			// data: decrypted padded data
			// length: length of padded data
			// return: pad size
			uint8_t unpad(uint8_t *&data, uint16_t &length);
	};


	// Elliptic Cryptography Digital Signature Algorithm
	class Ecdsa : public ErrorHandling
	{
		ProtocolData protocol;
		Key key;
		CryptoPP::AutoSeededRandomPool prng;
		std::vector<uint8_t> signature; // only for when signing, when verifying, give the parameter as uint8_t*

		// initialize signer
		void signer_init(auto signer, uint8_t *msg, uint16_t msg_len);
		
		public:

		// msg: message as the data segment. If image, msg_len is IMAGE_BUFFER_SIZE
		// msg_len: length of msg
		Ecdsa(ProtocolData &protocol, Key key);

		// returns signature as a vector
		// msg: message to sign
		// msg_len: length of message to sign
		void sign(uint8_t *msg, uint16_t msg_len);

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
		uint8_t *mac; // output mac

		// generator initializer
		// hmacf: hmac function
		// pt: plaintext
		// pt_len: plaintext length
		// mac_code: Message Authentecation Code unallocated buffer
		inline void generator_init(auto hmacf, uint8_t *pt, uint16_t pt_len);
		inline bool verifier_init(auto hmacf, uint8_t *pt, uint16_t len);

		public:
				Hmac(ProtocolData &protocol, uint8_t *key);

				~Hmac();

				inline uint8_t *get_mac();

				// generate the HMAC code
				void generate(uint8_t *pt, uint16_t len);

				bool verify(uint8_t *pt, uint16_t len);
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
