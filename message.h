#ifndef MESSAGE_H
#define MESSAGE_H

#include <cryptopp/filters.h>
#include <cryptopp/pubkey.h>
#include <cryptopp/sha.h>
#include <cstdlib>
#include <functional>
#include <string>
#include <concepts>
#include <stdlib.h>
#include <utility>
#include <variant>

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

#include <boost/asio/buffer.hpp>

#include <jsoncpp/json/json.h>

#include "settings.h"
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

	// 64-bit salt for HKDF
	const constexpr static uint8_t salt[8] = {0x8f, 0x49, 0xa8, 0x2c, 0x21, 0xb5, 0x96, 0x5c};
	const constexpr uint8_t salt_len = sizeof(salt)/sizeof(salt[0]);

	// the default values to assign
	// AES uses CBC mode (for performance reasons: https://cryptopp.com/benchmarks.html)
	inline uint8_t default_communication_protocol = (uint8_t)SECP256R1 + ECIES_HMAC_AES256_CBC_SHA256;
	inline uint16_t default_mac_size = 32;
	inline CryptoPP::OID default_elliptic_curve = CryptoPP::ASN1::secp256r1();
	inline VerificationAlgorithm default_verifier = HMAC;
	using default_cipher = CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption; // aes cbc mode
	using default_decipher = CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption; // aes cbc mode
	using default_hash = CryptoPP::SHA256;

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
				void hkdf();
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
		// mac_code: Message Authentecation Code unalocated buffer
		inline void generator_init(auto hmacf, uint8_t *pt, uint16_t pt_len);
		inline bool verifier_init(auto hmacf, uint8_t *pt, uint16_t len);

		public:
				Hmac(ProtocolData &protocol, uint8_t *key);

				~Hmac();

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
// decrypt(cipher, ciphertext, ciphertext_length, plaintext, length);
// pad_size = d.unpad(plaintext, length);
// delete[] plaintext;
// delete[] ciphertext;
//



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
template<typename T=std::string> // if message is TEXT, then make it string, else, uint8_t*
class Message
{
	public:
		std::string timestamp; // time of message
		T msg; // plaintext message to receive
		Json::Value messages;
		std::string messages_path;
		enum format {TEXT, IMAGE, VIDEO, _FILE_, GIF, DELETE};

		// message and time (optional)
		Message(T message, std::string tm, std::string message_path, std::string from, std::string to, Settings settings);

		// add to sessions/messages.json after encrypting, and compressing
		void add(std::string messages_path, format type=TEXT);
};

#endif /* MESSAGE_H */
