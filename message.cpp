#include <iostream>
#include <jsoncpp/json/json.h>
#include <ctime>
#include <chrono>
#include <string>

#include "message.h"

// TODO: secure messages

Cryptography::ProtocolData::ProtocolData(uint8_t protocol_no)
{
	init(protocol_no);
}

void Cryptography::ProtocolData::init(uint8_t protocol_no)
{
	// seperate protocol and curve
	protocol = (CommunicationProtocol)(protocol_no - protocol_no % LAST);
	curve = (Curves)(protocol_no % LAST);
	mac_size = default_mac_size;

	// initialize verification algorithm data
	if(communication_protocols[protocol].find("ECDSA") != std::string::npos) {
		verifier = ECDSA;
	} if(communication_protocols[protocol].find("HMAC") != std::string::npos) {
		verifier = HMAC;
	} else {
		error = VERIFICATION_ALGORITHM_NOT_FOUND;
	}
	error_handle(VERIFICATION_ALGORITHM_NOT_FOUND, error_handler_verifier_function_not_found, verification_unexpected_error, get_time);

	// initialize cipher and decipher object
	init_cipher_data();

	// if error caused: can only be ENCRYPTION_ALGORITHM_NOT_FOUND
	if (error != NO_ERROR) {
		error_handle(ENCRYPTION_ALGORITHM_NOT_FOUND, error_handler_encryption_function_not_found, encryption_unexpected_error, get_time);
	}

	curve_oid = get_curve();

	init_hash_data();
	if (error != NO_ERROR) {
		error_handle(HASHING_ALGORITHM_NOT_FOUND, error_handler_hash_function_not_found, hashing_unexpected_error, get_time);
	}
}

Cryptography::ProtocolData::ProtocolData(CommunicationProtocol protocol, Curves curve)
{
	this->protocol = protocol;
	this->curve = curve;

	init_cipher_data();
	error_handle(ENCRYPTION_ALGORITHM_NOT_FOUND, error_handler_encryption_function_not_found, encryption_unexpected_error, get_time);

	init_hash_data();
	error_handle(HASHING_ALGORITHM_NOT_FOUND, error_handler_hash_function_not_found, hashing_unexpected_error, get_time);
}

uint8_t *Cryptography::ProtocolData::generate_iv()
{
		uint8_t *tmp = new uint8_t[iv_size];
		CryptoPP::AutoSeededRandomPool rnd;
		rnd.GenerateBlock(tmp, iv_size);
		return tmp;
}


void Cryptography::ProtocolData::init_cipher_data()
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
	} else { // e.g. CHACHA20, no cipher mode
		cipher_mode = NO_MODE;
		cipherf = CryptoPP::ChaCha::Encryption();
		decipherf = CryptoPP::ChaCha::Encryption();
	}
}

// get information about the hashing algorithm used
// returns hashing algorithm if applicable
void Cryptography::ProtocolData::init_hash_data()
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

// to get cipher: auto cipher = get_cipher();
std::variant<CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption, // aes cbc mode
			   CryptoPP::GCM<CryptoPP::AES>::Decryption,      // aes gcm mode
			   CryptoPP::ChaCha::Encryption>                  // ChaCha20
			   Cryptography::ProtocolData::get_decipher()
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
			[[fallthrough]];
		case CHACHA20:
			return CryptoPP::ChaCha::Encryption();
		default:
			error = ENCRYPTION_ALGORITHM_NOT_FOUND;

			// default value
			return default_decipher();
	}
}

// to get cipher: auto cipher = get_cipher();
std::variant<CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption, // aes cbc mode
			   CryptoPP::GCM<CryptoPP::AES>::Encryption,      // aes gcm mode
			   CryptoPP::ChaCha::Encryption>                  // ChaCha20
			   Cryptography::ProtocolData::get_cipher()
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
			[[fallthrough]];
		case CHACHA20:
			return CryptoPP::ChaCha::Encryption();
		default:
			error = ENCRYPTION_ALGORITHM_NOT_FOUND;
			return default_cipher();
	}
}

// to get hash: auto hashf = get_hash();
std::variant<CryptoPP::SHA256, CryptoPP::SHA512> Cryptography::ProtocolData::get_hash()
{
	switch(hash) {
		case SHA256:
			return CryptoPP::SHA256();
		case SHA512:
			return CryptoPP::SHA512();
		default:
			return default_hash();
	}
}

// to get hash: auto hashf = get_curve();
// returns curve OID (Object ID)
CryptoPP::OID Cryptography::ProtocolData::get_curve()
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
		default:
			return default_elliptic_curve;
	}
}


// message and time
template<typename T>
Message<T>::Message(T message, std::string tm, std::string message_path, std::string from, std::string to, Settings settings)
{
	msg = message;
	timestamp = tm;
	messages_path = message_path;
}

// add to sessions/messages.json
template<typename T>
void Message<T>::add(std::string messages_path, format type)
{
	
}

std::string get_time()
{
    auto time = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(time);
	return std::ctime(&end_time);
}
