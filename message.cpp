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
			if(cipher_mode == GCM)
				return CryptoPP::GCM<CryptoPP::AES>::Encryption();

			// default mode
			return CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption();
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

Cryptography::Key::Key(ProtocolData &protocol) : protocol(protocol)
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

Cryptography::Key::~Key()
{
	delete[] key;
}

// convert public key to uint8_t*
void Cryptography::Key::integer_to_bytes(CryptoPP::Integer num, uint8_t *&bytes, uint16_t &bytes_len)
{
	bytes_len = num.MinEncodedSize(CryptoPP::Integer::UNSIGNED);
	bytes = new uint8_t[bytes_len];
	num.Encode((uint8_t*)&bytes[0], bytes_len, CryptoPP::Integer::UNSIGNED);
}

CryptoPP::Integer Cryptography::Key::bytes_to_integer(uint8_t *&bytes, uint16_t &bytes_len)
{
	CryptoPP::Integer x;
	x.Decode(bytes, bytes_len);
	return x;
}

CryptoPP::ECPPoint Cryptography::Key::reconstruct_point_from_bytes(uint8_t *public_key_x,
															  					 uint16_t public_key_x_len,
															  					 uint8_t *public_key_y,
															  					 uint16_t public_key_y_len)
{
	return CryptoPP::ECPPoint(Key::bytes_to_integer(public_key_x, public_key_x_len),
							  Key::bytes_to_integer(public_key_y, public_key_y_len));
}

// bob's public key is multiplied with alice's to generate the ECDH key.
CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>::Element
Cryptography::Key::multiply(CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>::Element b_public_k)
{
	return group.GetCurve().ScalarMultiply(b_public_k, private_key);
}

// bob's public key is multiplied with alice's to generate the ECDH key.
CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>::Element
Cryptography::Key::multiply(CryptoPP::Integer priv_key,
		 					CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>::Element b_public_k)
{
	return group.GetCurve().ScalarMultiply(b_public_k, priv_key);
}

// Hash based key deravation function
void Cryptography::Key::hkdf()
{
	if(protocol.hash == SHA256) {
		CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
	    hkdf.DeriveKey(key, protocol.key_size, (const uint8_t*)"", 0, salt, salt_len, NULL, 0);
	} else if (protocol.hash == SHA512) {
		CryptoPP::HKDF<CryptoPP::SHA512> hkdf;
	    hkdf.DeriveKey(key, protocol.key_size, (const uint8_t*)"", 0, salt, salt_len, NULL, 0);
	} else {
		error = HASHING_ALGORITHM_NOT_FOUND;

		// default value
		CryptoPP::HKDF<default_hash> hkdf;
	    hkdf.DeriveKey(key, protocol.key_size, (const uint8_t*)"", 0, salt, salt_len, NULL, 0);
	}
}

 //void operator()(CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption &enc)
 void Cryptography::Cipher::Encryptor::operator()(AesEncryptorCBC_GMC auto &enc) // added the requirement of AesEncryptor because the same function required for 2 types
 {
 	if(!init) {
 		ciphertext_length = plaintext_length<<1;
 		ciphertext = new uint8_t[ciphertext_length];
 	}
 	CryptoPP::StreamTransformationFilter filter(enc, new CryptoPP::ArraySink(ciphertext, ciphertext_length));
 	filter.Put(plaintext, plaintext_length);
 	filter.MessageEnd();
 	init = true;
 }

 // void operator()(CryptoPP::GCM<CryptoPP::AES>::Encryption &enc) // same function definition above if concept doesn't work

 void Cryptography::Cipher::Encryptor::operator()(CryptoPP::ChaCha::Encryption &enc)
 {
 	if(!init) {
 		ciphertext_length = plaintext_length;
 		ciphertext = new uint8_t[ciphertext_length];
 	}
 	enc.ProcessData((uint8_t*)&ciphertext[0], (const uint8_t*)plaintext, plaintext_length);
 	init = true;
 }

Cryptography::Cipher::Cipher(ProtocolData &protocol, uint8_t *key, uint8_t *iv) : protocol(protocol)
{
	this->key = key; // no need to destroy key since it's not allocated here.
	this->iv = iv; // no need to destroy key since it's not allocated here.
}

// set key with iv
void Cryptography::Cipher::set_key(auto cipher)
{
	cipher.setKeyWithIv(key, protocol.key_size, iv, protocol.iv_size);
}

// cipher: output of protocol.get_cipher()
// data: string, or uint8_t ptr, or buffer, etc. Plaintext
// length: data length, the send packet length. if 1GB image, it would be IMAGE_BUFFER_SIZE, if last packet. has to be padded to be a multiple of protocol.block_size.
// ct: ciphertext
// ct_len: ciphertext length
// mem_allocated: if memory is allocated, don't reallocate
void Cryptography::Cipher::encrypt(auto &data, uint16_t length, uint8_t *&ct, uint16_t &ct_len, bool &is_ct_allocated)
{
		uint8_t *pt; // padding assumed to be done, use the pad function for padding

		// data has to be uint8_t*
		pt = to_uint8_ptr(data);

		// check the encryption types
		encryptor.ciphertext = ct;
		encryptor.plaintext = pt;
		encryptor.ciphertext_length = ct_len;
		encryptor.plaintext_length = length;
		encryptor.init = is_ct_allocated;
		std::visit(encryptor, protocol.cipherf);

		//switch(protocol.cipher) {
		//	case CHACHA20:
		//		ct_len = length;
		//		ct = new uint8_t[ct_len];
		//		cipher.ProcessData((uint8_t*)&ct[0], (const uint8_t*)pt, length);
		//		//protocol.cipherf.ProcessData((uint8_t*)&ct[0], (const uint8_t*)pt, length);
		//		break;
		//	case AES256:
		//	case AES192:
		//	case AES128:
		//		ct_len = length<<1;
		//		ct = new uint8_t[ct_len];
		//		CryptoPP::StreamTransformationFilter filter(cipher, new CryptoPP::ArraySink(ct, ct_len));
		//		filter.Put(pt, length);
		//		filter.MessageEnd();
		//		break;
		//}
}

// to convert strings and boost buffers to uint8_t*
constexpr uint8_t *Cryptography::Cipher::to_uint8_ptr(auto data)
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
uint8_t *Cryptography::Cipher::pad(uint8_t *data, uint16_t &length)
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
