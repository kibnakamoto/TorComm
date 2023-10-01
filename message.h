#ifndef MESSAGE_H
#define MESSAGE_H

#include <cryptopp/filters.h>
#include <cstdlib>
#include <functional>
#include <string>
#include <concepts>
#include <stdlib.h>
#include <utility>

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

#include <boost/variant/variant.hpp>
#include <boost/asio/buffer.hpp>

#include <jsoncpp/json/json.h>

#include "settings.h"
#include "errors.h"

// get current time
std::string get_time();

// pt: plaintext
// key: encryption key
// ct: ciphertext, key

namespace Cryptography
{
	// GLOBAL:
	// 	 ECDH for key communication
	// 	 HKDF for key derevation
	enum CommunicationProtocol {

		ECIES_ECDSA_AES256_CBC_SHA256,
		ECIES_ECDSA_AES256_CBC_SHA512,
		ECIES_ECDSA_AES192_CBC_SHA256,
		ECIES_ECDSA_AES192_CBC_SHA512,
		ECIES_ECDSA_AES128_CBC_SHA256,
		ECIES_ECDSA_AES128_CBC_SHA512,

		ECIES_ECDSA_CHACHA20_SHA256,
		ECIES_ECDSA_CHACHA20_SHA512,
		LAST // not a value, just for iteration
	};

	const std::string communication_protocols[] {

		"ECIES_ECDSA_AES256_CBC_SHA256",
		"ECIES_ECDSA_AES256_CBC_SHA512",
		"ECIES_ECDSA_AES192_CBC_SHA256",
		"ECIES_ECDSA_AES192_CBC_SHA512",
		"ECIES_ECDSA_AES128_CBC_SHA256",
		"ECIES_ECDSA_AES128_CBC_SHA512",

		"ECIES_ECDSA_CHACHA20_CBC_SHA256",
		"ECIES_ECDSA_CHACHA20_CBC_SHA512",
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

	// 64-bit salt for HKDF
	const constexpr static uint8_t salt[8] = {0x8f, 0x49, 0xa8, 0x2c, 0x21, 0xb5, 0x96, 0x5c};
	const constexpr uint8_t salt_len = sizeof(salt)/sizeof(salt[0]);

	// the default values to assign
	// AES uses CBC mode (for performance reasons: https://cryptopp.com/benchmarks.html)
	inline uint8_t default_communication_protocol = (uint8_t)SECP256R1 + ECIES_ECDSA_AES256_CBC_SHA256;

	// initialize general protocol data based on protocol number
	class ProtocolData : public ErrorHandling
	{
		public:
			// hash
			boost::variant<CryptoPP::SHA256, CryptoPP::SHA512> hashf;

			// encrypt
			boost::variant<CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption, // aes cbc mode
						   CryptoPP::GCM<CryptoPP::AES>::Encryption,      // aes gcm mode
						   CryptoPP::ChaCha::Encryption>  cipherf;         // ChaCha20

			// decrypt
			boost::variant<CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption, // aes cbc mode
						   CryptoPP::GCM<CryptoPP::AES>::Decryption,      // aes gcm mode
						   CryptoPP::ChaCha::Encryption>                  // ChaCha20
						   decipherf;

			HashAlgorithm hash; // hashing algorithm used
			CipherAlgorithm cipher; // cipher used
			CipherMode cipher_mode; // cipher mode
			Curves curve; // Elliptic curve used
			CommunicationProtocol protocol; // not full communication protocol used, doesn't include elliptic curve used
			uint16_t iv_size;
			uint16_t key_size;
			uint16_t ct_size; // size of ciphertext block size
			
			// for efficient custom error checking
			ERRORS error_code = NO_ERROR;

			// block size of cipher. plaintext has to be a multiple of block_size (padded)
			uint16_t block_size;

			ProtocolData() = default;

			ProtocolData(uint8_t protocol_no)
			{
				init(protocol_no);
			}

			void init(uint8_t protocol_no)
			{
				// seperate protocol and curve
				protocol = (CommunicationProtocol)(protocol_no - protocol_no % LAST);
				curve = (Curves)(protocol_no % LAST);

				// initialize cipher and decipher object
				init_cipher_data();

				// if error caused: can only be ENCRYPTION_ALGORITHM_NOT_FOUND
				error_handle(ENCRYPTION_ALGORITHM_NOT_FOUND, error_handler_encryption_function_not_found, encryption_unexpected_error, get_time);

				init_hash_data();
				error_handle(HASHING_ALGORITHM_NOT_FOUND, error_handler_hash_function_not_found, hashing_unexpected_error, get_time);
			}

			ProtocolData(CommunicationProtocol protocol, Curves curve)
			{
				this->protocol = protocol;
				this->curve = curve;

				init_cipher_data();
				error_handle(ENCRYPTION_ALGORITHM_NOT_FOUND, error_handler_encryption_function_not_found, encryption_unexpected_error, get_time);

				init_hash_data();
				error_handle(HASHING_ALGORITHM_NOT_FOUND, error_handler_hash_function_not_found, hashing_unexpected_error, get_time);
			}

			uint8_t *generate_iv()
			{
					uint8_t *tmp = new uint8_t[iv_size];
					CryptoPP::AutoSeededRandomPool rnd;
					rnd.GenerateBlock(tmp, iv_size);
					return tmp;
			}


		private:
			// error handler for hash function not found
			std::function<void()> error_handler_hash_function_not_found=[]() {
				if (!USE_DEFAULT_VALUES) // defined in errors.h
					throw HASHING_ALGORITHM_NOT_FOUND;
				else
					ProtocolData(default_communication_protocol+0);
			};

			// error handler for encryption_algorithm_not_found
			std::function<void()> error_handler_encryption_function_not_found=[]() {
				if (!USE_DEFAULT_VALUES) // defined in errors.h
					throw ENCRYPTION_ALGORITHM_NOT_FOUND;
				else
					ProtocolData(default_communication_protocol+0);
			};

			void init_cipher_data()
			{
				ct_size=32;
				if(communication_protocols[protocol].find("AES256") != std::string::npos) {
					iv_size = 16;
					cipher = AES256;
					key_size = 32;
					block_size = 16;
				} else if (communication_protocols[protocol].find("AES192") != std::string::npos) {
					iv_size = 16;
					cipher = AES192;
					key_size = 24;
					block_size = 16;
				} else if (communication_protocols[protocol].find("AES128") != std::string::npos) {
					iv_size = 16;
					cipher = AES128;
					key_size = 16;
					block_size = 16;
				} else if (communication_protocols[protocol].find("CHACHA20") != std::string::npos) {
					iv_size = 12;
					cipher = CHACHA20;
					key_size = 32;
					block_size = ct_size;
				} else {
					error_code = ENCRYPTION_ALGORITHM_NOT_FOUND;
				}

				// set cipher mode
				if(communication_protocols[protocol].find("CBC") != std::string::npos) {
					cipher_mode = CBC;
					cipherf = CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption();
					decipherf = CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption();
				} else if(communication_protocols[protocol].find("GCM") != std::string::npos) {
					cipher_mode = GCM;
					cipherf = CryptoPP::GCM<CryptoPP::AES>::Encryption();
					decipherf = CryptoPP::GCM<CryptoPP::AES>::Decryption();
				} else { // e.g. CHACHA20
					cipher_mode = NO_MODE;
					cipherf = CryptoPP::ChaCha::Encryption();
					decipherf = CryptoPP::ChaCha::Encryption();
				}
			}
	
			// get information about the hashing algorithm used
			// returns hashing algorithm if applicable
			void init_hash_data()
			{
				if(communication_protocols[protocol].find("SHA256") != std::string::npos) {
					hash = SHA256;
					hashf = CryptoPP::SHA256();
				} else if(communication_protocols[protocol].find("SHA512") != std::string::npos) {
					hash = SHA512;
					hashf = CryptoPP::SHA512();
				} else {
					error_code = HASHING_ALGORITHM_NOT_FOUND;
				}
			}

		public:
			// to get cipher: auto cipher = get_cipher();
			boost::variant<CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption, // aes cbc mode
						   CryptoPP::GCM<CryptoPP::AES>::Decryption,      // aes gcm mode
						   CryptoPP::ChaCha::Encryption>                  // ChaCha20
						   get_decipher()
			{
				switch(cipher) {
					case AES256:
					case AES192:
					case AES128:
						if(cipher_mode == CBC) {
							return CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption();
						} else if(cipher_mode == GCM) {
							return CryptoPP::GCM<CryptoPP::AES>::Decryption();
						}
					case CHACHA20:
						return CryptoPP::ChaCha::Encryption();
					default:
						error = ENCRYPTION_ALGORITHM_NOT_FOUND;
						error_handle(ENCRYPTION_ALGORITHM_NOT_FOUND,
									 error_handler_encryption_function_not_found,
									 encryption_unexpected_error, get_time);
						get_cipher(); // try again
				}
			}

			// to get cipher: auto cipher = get_cipher();
			boost::variant<CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption, // aes cbc mode
						   CryptoPP::GCM<CryptoPP::AES>::Encryption,      // aes gcm mode
						   CryptoPP::ChaCha::Encryption>                  // ChaCha20
						   get_cipher()
			{
				switch(cipher) {
					case AES256:
					case AES192:
					case AES128:
						if(cipher_mode == CBC) {
							return CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption();
						} else if(cipher_mode == GCM) {
							return CryptoPP::GCM<CryptoPP::AES>::Encryption();
						}
					case CHACHA20:
						return CryptoPP::ChaCha::Encryption();
					default:
						error = ENCRYPTION_ALGORITHM_NOT_FOUND;
						error_handle(ENCRYPTION_ALGORITHM_NOT_FOUND,
									 error_handler_encryption_function_not_found,
									 encryption_unexpected_error, get_time);
						get_cipher(); // try again
				}
			}

			// to get hash: auto hashf = get_hash();
			boost::variant<CryptoPP::SHA256, CryptoPP::SHA512> get_hash()
			{
				switch(hash) {
					case SHA256:
						return CryptoPP::SHA256();
					case SHA512:
						return CryptoPP::SHA512();
				}
			}

			// to get hash: auto hashf = get_hash();
			// returns curve OID (Object ID)
			CryptoPP::OID get_curve()
			{
				switch(curve) {
					case SECP256K1:
						return CryptoPP::ASN1::secp256k1();
					case SECP256R1:
						return CryptoPP::ASN1::secp256r1();
					case SECP521R1:
						return CryptoPP::ASN1::secp521r1();
					case BRAINPOOL256R1:
						return CryptoPP::ASN1::brainpoolP256r1();
					case BRAINPOOL512R1:
						return CryptoPP::ASN1::brainpoolP512r1();
				}
			}
	};

	// initialize key
	class Key : public ErrorHandling
	{
		CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> group;
		ProtocolData protocol;

		public:
				CryptoPP::Integer private_key;
				CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>::Element public_key;
				uint8_t *key; // established key

				Key(ProtocolData &protocol) : protocol(protocol)
				{
					key = new uint8_t[protocol.key_size];
					switch(protocol.curve) {
						case SECP256K1:
							group.Initialize(CryptoPP::ASN1::secp256k1());
							break;
						case SECP256R1:
							group.Initialize(CryptoPP::ASN1::secp256r1());
							break;
						case SECP521R1:
							group.Initialize(CryptoPP::ASN1::secp521r1());
							break;
						case BRAINPOOL256R1:
							group.Initialize(CryptoPP::ASN1::brainpoolP256r1());
							break;
						case BRAINPOOL512R1:
							group.Initialize(CryptoPP::ASN1::brainpoolP512r1());
							break;
						default:
							error = ELLIPTIC_CURVE_NOT_FOUND;
							error_handle(ELLIPTIC_CURVE_NOT_FOUND,
							[protocol]() mutable { // elliptic curve not found
								if (!USE_DEFAULT_VALUES) // defined in errors.h
									throw ELLIPTIC_CURVE_NOT_FOUND;
								else
									protocol.init(default_communication_protocol+0);
							},
							ErrorHandling::curve_unexpected_error, get_time);
					}
					CryptoPP::AutoSeededRandomPool rand;
					private_key = CryptoPP::Integer(rand, CryptoPP::Integer::One(), group.GetMaxExponent()); // generate private key
					public_key  = group.ExponentiateBase(private_key);
				}

				~Key()
				{
					delete[] key;
				}

				// bob's public key is multiplied with alice's to generate the ECDH key.
				inline CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>::Element multiply(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>::Element b_public_k)
				{
					return group.GetCurve().ScalarMultiply(b_public_k, private_key);
				}

				// Hash based key deravation function
				void hkdf()
				{
					if(protocol.hash == SHA256) {
						CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
					    hkdf.DeriveKey(key, protocol.key_size, (const uint8_t*)"", 0, salt, salt_len, NULL, 0);
					} else if (protocol.hash == SHA512) {
						CryptoPP::HKDF<CryptoPP::SHA512> hkdf;
					    hkdf.DeriveKey(key, protocol.key_size, (const uint8_t*)"", 0, salt, salt_len, NULL, 0);
					} else {
						error = HASHING_ALGORITHM_NOT_FOUND;
					}
				}
	};

	// encryption
	class Cipher : public ErrorHandling
	{
		ProtocolData protocol;
		uint8_t *key; // key length is protocol.key_size
		uint8_t *iv; // iv length is protocol.iv_size
		public:
				

				Cipher(ProtocolData &protocol, uint8_t *key, uint8_t *iv) : protocol(protocol)
				{
					this->key = key; // no need to destroy key since it's not allocated here.
					this->iv = iv; // no need to destroy key since it's not allocated here.
				}

				// set key with iv
				void set_key(auto cipher)
				{
					cipher.setKeyWithIv(key, protocol.key_size, iv, protocol.iv_size);
				}

				// https://stackoverflow.com/questions/42817362/encrypt-decrypt-byte-array-crypto#42820221

				// cipher: output of protocol.get_cipher()
				// data: string, or uint8_t ptr, or buffer, etc. Plaintext
				// length: data length, the send packet length. if 1GB image, it would be IMAGE_BUFFER_SIZE, if last packet. has to be padded to be a multiple of protocol.block_size.
				// ct: ciphertext
				// ct_len: ciphertext length
				void encrypt(auto cipher, auto data, uint16_t length, uint8_t *ct, uint16_t &ct_len)
				{
						uint8_t *pt; // padding assumed to be done, use the pad function for padding

						// data has to be uint8_t*
						pt = to_uint8_ptr(data);

						// check the encryption types
						switch(protocol.cipher) {
							case CHACHA20:
								ct_len = length;
								ct = new uint8_t[ct_len];
					 			cipher.ProcessData((uint8_t*)&ct[0], (const uint8_t*)pt, length);
								break;
							case AES256:
							case AES192:
							case AES128:
								ct_len = length<<1;
								ct = new uint8_t[ct_len];
								CryptoPP::StreamTransformationFilter filter(cipher, new CryptoPP::ArraySink(ct, ct_len));
								filter.Put(pt, length);
  								filter.MessageEnd();
								break;
						}
				}

				// this assumes that the ciphertext length is given as well as ct memory is allocated
				// this should be used if encrypting data segments of the same length many times so that it doesn't reallocate and instead reuses ciphertext
				void encrypt(auto cipher, auto data, uint16_t length, uint16_t ct_len, uint8_t *ct)
				{
						uint8_t *pt; // padding assumed to be done, use the pad function for padding

						// data has to be uint8_t*
						pt = to_uint8_ptr(data);

						// check the encryption types
						switch(protocol.cipher) {
							case CHACHA20:
					 			cipher.ProcessData((uint8_t*)&ct[0], (const uint8_t*)pt, length);
								break;
							case AES256:
							case AES192:
							case AES128:
								CryptoPP::StreamTransformationFilter filter(cipher, new CryptoPP::ArraySink(ct, ct_len));
								filter.Put(pt, length);
  								filter.MessageEnd();
								break;
						}
				}


				// to convert strings and boost buffers to uint8_t*
				static constexpr uint8_t *to_uint8_ptr(auto data)
				{
					if constexpr(std::is_same<decltype(data), std::string>()) {
						return data.c_str();
					} else if constexpr(std::is_same<decltype(data), boost::asio::const_buffers_1>() ||
										std::is_same<decltype(data), boost::asio::mutable_buffers_1>()) { // convert buffer to uint8_t*
						return boost::asio::buffer_cast<uint8_t*>(data);
					} else { // uint8_t*
						return data;
					}
				}

				// reminder: length of data is the length of plaintext data to send. Data packet. Not the whole data

				// data: plaintext bytearray. Must be allocated using new uint8_t[length]
				// length: length of data
				// pad_size: pad_size
				// Pads the data from left to right. no need to remove padding, just remove the first zero digits
				uint8_t *pad(uint8_t *data, uint16_t &length)
				{
				    uint8_t *dat;
					uint8_t pad_size;
				    uint16_t original_length = length;
					uint16_t mod = length % protocol.block_size;
				    pad_size = protocol.block_size - mod;
					if(mod == 0) // if 32-byte unpadded, then pad_size=0, if zero, than dat[length-1] = pad_size would modify the plaintext
						pad_size += protocol.block_size;
				    length += pad_size;
				    dat = new uint8_t[length];
				    // memcpy(&dat[pad_size], data, original_length); // for left to right padding
				    memcpy(dat, data, original_length);				  // for right to left padding (append to end of message)
					dat[length-1] = pad_size; // last digit of data is length
				    delete[] data;
				    return dat;
				}

	};

	// encryption
	class Decipher : public ErrorHandling
	{
		ProtocolData protocol;
		uint8_t *key; // key length is protocol.key_size
		uint8_t *iv; // iv length is protocol.iv_size
		public:

			Decipher(ProtocolData &protocol, uint8_t *key, uint8_t *iv) : protocol(protocol)
			{
				this->key = key; // no need to destroy key since it's not allocated here.
				this->iv = iv; // no need to destroy key since it's not allocated here.
			}

			// cipher: output of protocol.get_decipher()
			// ct: ciphertext
			// ct_len: ciphertext length
			// data: plaintext
			// length: data length, the send packet length. if 1GB image, it would be IMAGE_BUFFER_SIZE, if last packet. has to be padded to be a multiple of protocol.block_size.
			// decrypts data, doesn't remove padding
			void decrypt(auto cipher, auto ct, uint16_t &ct_len, uint8_t *pt, uint16_t length)
			{
					uint8_t *data;

					// data has to be uint8_t*
					data = Cipher::to_uint8_ptr(ct);

					// check the encryption types
					switch(protocol.cipher) {
						case CHACHA20:
							length = ct_len;
							pt = new uint8_t[length];
				 			cipher.ProcessData(&pt[0], (const uint8_t*)data, length);
							break;
						case AES256:
						case AES192:
						case AES128:
							length = ct_len>>1;
							pt = new uint8_t[length];
							CryptoPP::StreamTransformationFilter filter(cipher, new CryptoPP::ArraySink(pt, length));
							filter.Put(ct, ct_len);
  							filter.MessageEnd();
							break;
					}
			}
			
			// set key with iv
			void set_key(auto cipher)
			{
				cipher.setKeyWithIv(key, protocol.key_size, iv, protocol.iv_size);
			}

			// remove padding
			// the last value of data is pad size to remove
			// keep the pad size from the original length. delete it accordingly
			// to delete:
			//		delete[] (data-pad_size);
			// data: decrypted padded data
			// length: length of padded data
			// return: pad size
			uint8_t unpad(uint8_t *&data, uint16_t &length)
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
	};


	// Elliptic Cryptography Digital Signature Algorithm
	class Ecdsa : public ErrorHandling
	{
		ERRORS error = NO_ERROR;
		ProtocolData protocol;
		Key key;

		Ecdsa(ProtocolData &protocol, Key key) : protocol(protocol), key(key)
		{
		}

		bool verify()
		{
			return 0;
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
// protocol = ProtocolData(Secp256r1 + ECIES_ECDSA_AES256_CBC_SHA256);

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
// delete[] (plaintext-pad_size);
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
