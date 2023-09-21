#include <functional>
#ifndef MESSAGE_H
#define MESSAGE_H

#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/integer.h>
#include <cryptopp/hkdf.h>

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
	// 	 AES uses CBC mode (for performance reasons: https://cryptopp.com/benchmarks.html)
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
		CBC, // currently the only supported one
		GCM
	};

	enum HashAlgorithm {
		SHA256,
		SHA512
	};

	// the default values to assign
	uint8_t default_communication_protocol = (uint8_t)Cryptography::SECP256R1 + Cryptography::ECIES_ECDSA_AES256_CBC_SHA256;

	// initialize general protocol data based on protocol number
	class ProtocolData
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
				error_handle(ENCRYPTION_ALGORITHM_NOT_FOUND, error_handler_encryption_function_not_found, encryption_unexpected_error);

				init_hash_data();
				error_handle(HASHING_ALGORITHM_NOT_FOUND, error_handler_hash_function_not_found, hashing_unexpected_error);
			}

			ProtocolData(CommunicationProtocol protocol, Curves curve)
			{
				this->protocol = protocol;
				this->curve = curve;

				init_cipher_data();
				error_handle(ENCRYPTION_ALGORITHM_NOT_FOUND, error_handler_encryption_function_not_found, encryption_unexpected_error);

				init_hash_data();
				error_handle(HASHING_ALGORITHM_NOT_FOUND, error_handler_hash_function_not_found, hashing_unexpected_error);
			}

			// lambda function is for what to do in case of error
			void error_handle(ERRORS check_error, auto&& lambda_for_error, auto&& lambda_for_unexpected_error)
			{
				// if error caused: can only be ENCRYPTION_ALGORITHM_NOT_FOUND
				if(error_code != NO_ERROR) {
					if(error_code == check_error) {
						error_code = NO_ERROR; // assign error code to None
						lambda_for_error();
					} else {
						// if a different error raised: unexpected behaviour
						error_code = NO_ERROR; // replace error code with None
						lambda_for_unexpected_error();
					}
				}
			}

		private:
			// error handler for hash function not found
			std::function<void()> error_handler_hash_function_not_found=[](){
				if constexpr(!USE_DEFAULT_VALUES) // defined in errors.h
					throw HASHING_ALGORITHM_NOT_FOUND;
				else
					ProtocolData(default_communication_protocol+0);
			};

			// error handler for encryption_algorithm_not_found
			std::function<void()> error_handler_encryption_function_not_found=[](){
				if constexpr(!USE_DEFAULT_VALUES) // defined in errors.h
					throw ENCRYPTION_ALGORITHM_NOT_FOUND;
				else
					ProtocolData(default_communication_protocol+0);
			};

			// find error and raise it after adding to a log file
			std::function<void(ERRORS)> encryption_unexpected_error=[](ERRORS error_code){
				std::ofstream file("error.log", std::fstream::in | std::fstream::out | std::fstream::app);
				file << "\nENCRYPTION UNEXPECTED ERROR (in Cryptography::ProtocolData::init_cipher_data) = TIME: " << get_time() << "\tERROR_CODE: " << error_code << "\tERROR_ID: " << ERROR_STRING[error_code];
				file.close();

				throw error_code;
			};

			// find error and raise it after adding to a log file
			std::function<void(ERRORS)> hashing_unexpected_error=[](ERRORS error_code){
				std::ofstream file("error.log", std::fstream::in | std::fstream::out | std::fstream::app);
				file << "\nHASHING UNEXPECTED ERROR (in Cryptography::ProtocolData::init_hash_data) = TIME: " << get_time() << "\tERROR_CODE: " << error_code << "\tERROR_ID: " << ERROR_STRING[error_code];
				file.close();

				throw error_code;
			};

			// currently only supports AES256
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

	class Key
	{
		CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> group;
		ERRORS error = NO_ERROR;

		public:
				CryptoPP::Integer private_key;
				CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>::Element public_key;
				CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>::Element cipher_key; // established key

				Key(Curves p=SECP256R1)
				{
					switch(p) {
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

				void hkdf(CommunicationProtocol protocol)
				{
					// if sha256

					if(communication_protocols[protocol].find("SHA256") != std::string::npos) {
						CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
					    //hkdf.DeriveKey(key, key.size(), (const byte*)password.data(), password.size(), (const byte*)iv.data(), iv.size(), NULL, 0);
					} else if (communication_protocols[protocol].find("SHA512") != std::string::npos) {
						
					} else {
						error = HASHING_ALGORITHM_NOT_FOUND;
					}
						
				}
	};

	// encryption
	class Cipher
	{
		public:
				Cipher(uint8_t protocol=(uint8_t)SECP256K1 + ECIES_ECDSA_AES256_CBC_SHA256) 
				{
					switch(protocol) {
						//case SECP256K1 + ECIES_ECDSA_AES256_CBC_SHA256:

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
