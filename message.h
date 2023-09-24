#ifndef MESSAGE_H
#define MESSAGE_H
#include <functional>
#include <string>

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

#include <boost/variant/variant.hpp>

#include <jsoncpp/json/json.h>

#include "settings.h"
#include "errors.h"

// get current time
std::string get_time();

// pt: plaintext
// key: encryption key
// ct: ciphertext, key

// IMPORTANT:  only ECIES_ECDSA_AES256_CBC_SHA256 supported for now
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

		ECIES_ECDSA_CHACHA20_CBC_SHA256,
		ECIES_ECDSA_CHACHA20_CBC_SHA512,
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

			HashAlgorithm hash; // hashing algorithm used
			CipherAlgorithm cipher; // cipher used
			CipherMode cipher_mode; // cipher mode
			Curves curve; // Elliptic curve used
			CommunicationProtocol protocol; // full communication protocol used
			uint16_t iv_size;
			uint16_t key_size;
			
			// for efficient custom error checking
			ERRORS error_code = NO_ERROR;

			// block size of cipher. plaintext has to be a multiple of block_size (padded)
			uint16_t block_size;

			ProtocolData(uint8_t protocol_no)
			{
				// seperate protocol and curve
				protocol = (CommunicationProtocol)(protocol_no - protocol_no % LAST);
				curve = (Curves)(protocol_no % LAST);
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
					block_size = 16;
				} else {
					error_code = ENCRYPTION_ALGORITHM_NOT_FOUND;
				}

				// set cipher mode
				if(communication_protocols[protocol].find("CBC") != std::string::npos) {
					cipher_mode = CBC;
				} else if(communication_protocols[protocol].find("CBC") != std::string::npos) {
					cipher_mode = GCM;
				}
			}
	
			// get information about the hashing algorithm used
			void init_hash_data()
			{
				if(communication_protocols[protocol].find("SHA256") != std::string::npos) {
					hash = SHA256;
				} else if(communication_protocols[protocol].find("SHA512") != std::string::npos) {
					hash = SHA512;
				} else {
					error_code = HASHING_ALGORITHM_NOT_FOUND;
				}
			}

	};

	// initialize key
	class Key : public ErrorHandling
	{
		CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> group;
		ProtocolData &protocol;

		public:
				CryptoPP::Integer private_key;
				CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>::Element public_key;
				uint8_t *key; // established key

				Key(ProtocolData &protocol) : protocol(protocol)
				{
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
							error = ELLIPTIC_CURVE_NOT_FOUND; // TODO: implement error handling
					}
					CryptoPP::AutoSeededRandomPool rand;
					private_key = CryptoPP::Integer(rand, CryptoPP::Integer::One(), group.GetMaxExponent()); // generate private key
					public_key  = group.ExponentiateBase(private_key);
				}

				// bob's public key is multiplied with alice's to generate the ECDH key.
				inline CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>::Element multiply(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>::Element b_public_k)
				{
					return group.GetCurve().ScalarMultiply(b_public_k, private_key);
				}

				void hkdf()
				{
					if(protocol.hash == SHA256) {
						CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
					    hkdf.DeriveKey(key, protocol.block_size, (const uint8_t*)"", 0, salt, salt_len, NULL, 0);
					} else if (protocol.hash == SHA512) {
						CryptoPP::HKDF<CryptoPP::SHA512> hkdf;
					    hkdf.DeriveKey(key, protocol.block_size, (const uint8_t*)"", 0, salt, salt_len, NULL, 0);
					} else {
						error = HASHING_ALGORITHM_NOT_FOUND;
					}
				}
	};

	// encryption
	class Cipher : public ErrorHandling
	{
		ProtocolData &protocol;

		public:
				

				Cipher(ProtocolData &protocol) : protocol(protocol)
				{
					
				}

				boost::variant<CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption, // aes cbc mode
							   CryptoPP::GCM<CryptoPP::AES>::Encryption  // aes gcm mode
							   > get_cipher()
				{
					switch(protocol.cipher) {
						case AES256:
						case AES192:
						case AES128:
							if(protocol.cipher_mode == CBC) {
								return CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption();
							} else if(protocol.cipher_mode == GCM) {
								return CryptoPP::GCM<CryptoPP::AES>::Encryption();
							}
						case CHACHA20:
						default:
							error = ENCRYPTION_ALGORITHM_NOT_FOUND;
							break;
					}
				}
	};

}; /* namespace Cryptography */


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
