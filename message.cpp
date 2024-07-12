#include <iostream>
#include <ctime>
#include <chrono>
#include <stdexcept>
#include <string>
#include <variant>

#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
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

#include "message.h"
#include "errors.h"

#include <boost/asio/buffer.hpp>

#include <json/json.h>

// key_path: path to keys file
// ct_ip: ciphertext of ip
// ct_ip_len: length of ct_ip
// iv: 16-byte iv
std::string Cryptography::decrypt_ip_with_pepper(std::string key_path, uint8_t *ct_ip, uint16_t ct_ip_len, uint8_t *iv)
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
uint8_t *Cryptography::encrypt_ip_with_pepper(std::string key_path, std::string ip, uint16_t &out_len, uint8_t *iv)
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

Cryptography::ProtocolData::ProtocolData(uint8_t protocol_no)
{
	init(protocol_no);
}

void Cryptography::ProtocolData::init(uint8_t protocol_no)
{
	// seperate protocol and curve
	protocol = (CommunicationProtocol)(protocol_no % LAST);
	uint16_t tmp = protocol_no - protocol_no % LAST;
	if(tmp != 0) {
		tmp /= LAST;
	}	
	curve = (Curves)(tmp);

	// initialize verification algorithm data
	if(communication_protocols[protocol].find("ECDSA") != std::string::npos) {
		verifier = ECDSA;
	} if(communication_protocols[protocol].find("HMAC") != std::string::npos) {
		verifier = HMAC;
	} else {
		#if DEBUG_MODE
			throw std::runtime_error("ProtocolData::init: VERIFICATION_ALGORITHM_NOT_FOUND error. The protocol number is not valid");
		#endif
		error = VERIFICATION_ALGORITHM_NOT_FOUND;
	}


	// initialize cipher and decipher object
	init_cipher_data();

	// if (error == ENCRYPTION_ALGORITHM_NOT_FOUND) {
	//	error_handle(ENCRYPTION_ALGORITHM_NOT_FOUND, error_handler_encryption_function_not_found, encryption_unexpected_error, get_time);
	// }

	curve_oid = get_curve();

	init_hash_data();
	// if (error == HASHING_ALGORITHM_NOT_FOUND) {
	//	error_handle(HASHING_ALGORITHM_NOT_FOUND, error_handler_hash_function_not_found, hashing_unexpected_error, get_time);
	// }
}

Cryptography::ProtocolData::ProtocolData(CommunicationProtocol protocol, Curves curve)
{
	this->protocol = protocol;
	this->curve = curve;

	init_cipher_data();
	// if (error == ENCRYPTION_ALGORITHM_NOT_FOUND) {
	// 	error_handle(ENCRYPTION_ALGORITHM_NOT_FOUND, error_handler_encryption_function_not_found, encryption_unexpected_error, get_time);
	// }

	init_hash_data();
	// if (error == HASHING_ALGORITHM_NOT_FOUND) {
	// 	error_handle(HASHING_ALGORITHM_NOT_FOUND, error_handler_hash_function_not_found, hashing_unexpected_error, get_time);
	// }
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
		iv_size = 8;
		cipher = CHACHA20;
		key_size = 32;
		block_size = ct_size;
	} else {
		error = ENCRYPTION_ALGORITHM_NOT_FOUND;
	}

	// set cipher mode
	if(communication_protocols[protocol].find("CBC") != std::string::npos) {
		cipher_mode = CBC;
	} else if(communication_protocols[protocol].find("GCM") != std::string::npos) {
		cipher_mode = GCM;
	} else { // e.g. CHACHA20, no cipher mode
		cipher_mode = NO_MODE;
	}
}

// get information about the hashing algorithm used
// returns hashing algorithm if applicable
void Cryptography::ProtocolData::init_hash_data()
{
	if(communication_protocols[protocol].find("SHA256") != std::string::npos) {
		hash = SHA256;
		hashf = CryptoPP::SHA256();
		mac_size = 32;
	} else if(communication_protocols[protocol].find("SHA512") != std::string::npos) {
		hash = SHA512;
		hashf = CryptoPP::SHA512();
		mac_size = 64;
	} else {
		error = HASHING_ALGORITHM_NOT_FOUND;
		mac_size = default_mac_size;
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
			#if DEBUG_MODE
				throw std::runtime_error("ProtocolData::get_decipher: ENCRYPTION_ALGORITHM_NOT_FOUND error. AES algorithm selected but no mode");
			#endif
			error = ENCRYPTION_ALGORITHM_NOT_FOUND;
			return default_decipher();
		case CHACHA20:
			return CryptoPP::ChaCha::Encryption();
		default:
			#if DEBUG_MODE
				throw std::runtime_error("ProtocolData::get_decipher: ENCRYPTION_ALGORITHM_NOT_FOUND error. The protocol number is not valid");
			#endif
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
			} else if(cipher_mode == GCM)
				return CryptoPP::GCM<CryptoPP::AES>::Encryption();

			// default mode
			#if DEBUG_MODE
				throw std::runtime_error("ProtocolData::get_cipher: ENCRYPTION_ALGORITHM_NOT_FOUND error. AES algorithm selected but no mode");
			#endif
			error = ENCRYPTION_ALGORITHM_NOT_FOUND;
			return default_cipher();
		case CHACHA20:
			return CryptoPP::ChaCha::Encryption();
		default:
			#if DEBUG_MODE
				throw std::runtime_error("ProtocolData::get_cipher: ENCRYPTION_ALGORITHM_NOT_FOUND error. The protocol number is not valid");
			#endif
			error = ENCRYPTION_ALGORITHM_NOT_FOUND;

			// default value
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
			#if DEBUG_MODE
				throw std::runtime_error("ProtocolData::get_hash: HASHING_ALGORITHM_NOT_FOUND error. The protocol number is not valid");
			#endif
			error = HASHING_ALGORITHM_NOT_FOUND;
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
			#if DEBUG_MODE
				throw std::runtime_error("ProtocolData::get_hash: ELLIPTIC_CURVE_NOT_FOUND error. The protocol number is not valid");
			#endif
			error = ELLIPTIC_CURVE_NOT_FOUND;

			// error handling
			// error_handle(ELLIPTIC_CURVE_NOT_FOUND,
			// [protocol]() mutable { // elliptic curve not found
			// 	if (!USE_DEFAULT_VALUES) // defined in errors.h
			// 		throw ELLIPTIC_CURVE_NOT_FOUND;
			// 	else
			// 		protocol.init(default_communication_protocol+0);
			// },
			// ErrorHandling::curve_unexpected_error, get_time);
			
			// default value
			group.Initialize(default_elliptic_curve);
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

CryptoPP::Integer Cryptography::Key::bytes_to_integer(uint8_t *bytes, uint16_t &bytes_len)
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
// password: ECDH Shared Secret
// password_len: length of password
// salt: optional salt
// salt_len: length of salt
// info: optional info
// info_len: length of info
void Cryptography::Key::hkdf(uint8_t *password, uint16_t password_len, uint8_t *salt, uint16_t salt_len, uint8_t *info, uint16_t info_len)
{
	if(protocol.hash == SHA256) {
		CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
	    hkdf.DeriveKey(key, protocol.key_size, password, password_len, salt, salt_len, info, info_len);
	} else if (protocol.hash == SHA512) {
		CryptoPP::HKDF<CryptoPP::SHA512> hkdf;
	    hkdf.DeriveKey(key, protocol.key_size, password, password_len, salt, salt_len, info, info_len);
	} else {
		#if DEBUG_MODE
			throw std::runtime_error("Key::hkdf: HASHING_ALGORITHM_NOT_FOUND error. The protocol number is not valid");
		#endif
		error = HASHING_ALGORITHM_NOT_FOUND;

		// default value
		CryptoPP::HKDF<default_hash> hkdf;
	    hkdf.DeriveKey(key, protocol.key_size, (const uint8_t*)"", 0, salt, salt_len, NULL, 0);
	}
}

Cryptography::Cipher::Cipher(ProtocolData &protocol, uint8_t *key) : protocol(protocol)
{
	this->key = key; // no need to destroy key since it's not allocated here.

	switch(protocol.cipher) {
		case AES256:
		case AES192:
		case AES128: 
			if(protocol.cipher_mode == CBC) {
				selected = 0;
			} else {
				selected = 1;
			}
			break;
		case CHACHA20:
			selected = 2;
			break;
	}
}

void Cryptography::Cipher::assign_iv(uint8_t *iv)
{
	this->iv = iv;
}

void Cryptography::Cipher::assign_key(uint8_t *key)
{
	this->key = key;
}

// void Cryptography::Decipher::Decryptor::operator()(AesDecryptorCBC_GMC auto &dec)
// {
// 	if(!init) {
// 		plaintext_length = ciphertext_length>>1;
// 		plaintext = new uint8_t[plaintext_length];
// 	}
// 	CryptoPP::StreamTransformationFilter filter(dec, new CryptoPP::ArraySink(plaintext, plaintext_length), CryptoPP::StreamTransformationFilter::NO_PADDING);
// 	filter.Put(ciphertext, ciphertext_length);
// 	filter.MessageEnd();
// 	init = true;
// }
// 
// void Cryptography::Decipher::Decryptor::operator()(CryptoPP::ChaCha::Encryption &dec)
// {
// 	if(!init) {
// 		plaintext_length = ciphertext_length;
// 		plaintext = new uint8_t[plaintext_length];
// 	}
// 	dec.ProcessData(&plaintext[0], (const uint8_t*)ciphertext, ciphertext_length);
// 	init = true;
// }

Cryptography::Decipher::Decipher(ProtocolData &protocol, uint8_t *key) : protocol(protocol)
{
	this->key = key; // no need to destroy key since it's not allocated here.

	switch(protocol.cipher) {
		case AES256:
		case AES192:
		case AES128: 
			if(protocol.cipher_mode == CBC) {
				selected = 0;
			} else {
				selected = 1;
			}
			break;
		case CHACHA20:
			selected = 2;
			break;
	}
}

// cipher: output of protocol.get_decipher()
// ct: ciphertext
// ct_len: ciphertext length
// pt: plaintext
// length: pt length
// decrypts data, doesn't remove padding
void Cryptography::Decipher::decrypt(uint8_t *ct, uint64_t ct_len, uint8_t *pt, uint64_t length)
{
	switch(selected) {
		case 0:
			{
				dec1.SetKeyWithIV(key, protocol.key_size, iv, protocol.iv_size);
				CryptoPP::StreamTransformationFilter filter(dec1, new CryptoPP::ArraySink(pt, length), CryptoPP::StreamTransformationFilter::NO_PADDING);
				filter.Put(ct, ct_len);
				filter.MessageEnd();
			}
			break;
		case 1:
			{
				dec2.SetKeyWithIV(key, protocol.key_size, iv, protocol.iv_size);
				CryptoPP::AuthenticatedDecryptionFilter filter(dec2, new CryptoPP::ArraySink(pt, length), CryptoPP::StreamTransformationFilter::NO_PADDING);
				filter.Put(ct, ct_len);
				filter.MessageEnd();
			}
			break;
		case 2:
			dec3.SetKeyWithIV(key, protocol.key_size, iv, protocol.iv_size);
		 	dec3.ProcessData(pt, ct, ct_len);
			break;
	}
}

// assign iv
void Cryptography::Decipher::assign_iv(uint8_t *iv)
{
	this->iv = iv;
}

// assign key
void Cryptography::Decipher::assign_key(uint8_t *key)
{
	this->key = key;
}

void Cryptography::Ecdsa::signer_init(auto signer, uint8_t *msg, uint16_t msg_len)
{
	signer.AccessKey().Initialize(protocol.curve_oid, key.private_key);
	CryptoPP::StringSource s(msg, msg_len, true,
    						 new CryptoPP::SignerFilter(prng,
									 		  			signer,
											  			new CryptoPP::VectorSink(signature)));
}

// msg: message as the data segment. If image, msg_len is IMAGE_BUFFER_SIZE
// msg_len: length of msg
// Cryptography::Ecdsa::Ecdsa(ProtocolData &protocol, Key key) : protocol(protocol), key(key) {}

// returns signature as a vector
// msg: message to sign
// msg_len: length of message to sign
void Cryptography::Ecdsa::sign(uint8_t *msg, uint16_t msg_len)
{
	if(protocol.hash == SHA256) {
		CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer signer;
		signer_init(signer, msg, msg_len);
	} else if(protocol.hash == SHA512) {
		CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA512>::Signer signer;
		signer_init(signer, msg, msg_len);
	} else {
		#if DEBUG_MODE
			throw std::runtime_error("Ecdsa::sign: HASHING_ALGORITHM_NOT_FOUND error. The protocol number is not valid");
		#endif
		error = HASHING_ALGORITHM_NOT_FOUND;

		// give it the default value
		CryptoPP::ECDSA<CryptoPP::ECP, default_hash>::Signer signer;
		signer_init(signer, msg, msg_len);
	}
}

// public key is received as bytes. Convert to ECPoint using: Key::reconstruct_point_from_bytes
// msg: message to verify
// msg_len: length of msg
// signature: ECDSA signature
// signature_len: length of signature
// public_key: received public key. Not the own public key
bool Cryptography::Ecdsa::verify(uint8_t *msg, uint16_t msg_len, uint8_t *&signature, uint16_t signature_len,
			CryptoPP::ECPPoint public_key)
{
	bool verified;
	if(protocol.hash == SHA256) {
		CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey public_k;
		public_k.Initialize(protocol.curve_oid, public_key); // init public key
		CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier verifier(public_k);
		verified = verifier.VerifyMessage(&msg[0], msg_len, &signature[0], signature_len); // ecdsa message verification
	} else if(protocol.hash == SHA512) {
		CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA512>::PublicKey public_k;
		public_k.Initialize(protocol.curve_oid, public_key); // init public key
		CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA512>::Verifier verifier(public_k);
		verified = verifier.VerifyMessage(&msg[0], msg_len, &signature[0], signature_len); // ecdsa message verification
	} else {
		#if DEBUG_MODE
			throw std::runtime_error("Ecdsa::verify: HASHING_ALGORITHM_NOT_FOUND error. The protocol number is not valid");
		#endif
		error = HASHING_ALGORITHM_NOT_FOUND;

		// default hash value
		CryptoPP::ECDSA<CryptoPP::ECP, default_hash>::PublicKey public_k;
		public_k.Initialize(protocol.curve_oid, public_key); // init public key
		CryptoPP::ECDSA<CryptoPP::ECP, default_hash>::Verifier verifier(public_k);
		verified = verifier.VerifyMessage(&msg[0], msg_len, &signature[0], signature_len); // ecdsa message verification
	}

	return verified;
}

// returns the length of out buffer, gets the compressed x value with the 03 starting byte
template<Cryptography::SupportedHashAlgs HashAlg>
uint16_t Cryptography::Ecdsa::get_compressed(CryptoPP::ECDSA<CryptoPP::ECP, HashAlg> &public_key, uint8_t *out_buffer)
{
	CryptoPP::Integer x = public_key.GetPublicElement().x;
	uint16_t bytes_len = x.MinEncodedSize(CryptoPP::Integer::UNSIGNED);
	out_buffer = new uint8_t[bytes_len+1];
	x.Encode(&out_buffer[1], bytes_len, CryptoPP::Integer::UNSIGNED);
	out_buffer[0] = 0x03; // first byte is 03 to denote that it's compressed. When received public key, check if out_buffer is compressed then call get_decompressed
	bytes_len++;
	return bytes_len;
}

// public_key: 03 concatinated with x-coordinate of the public key
// public_key_len: length of public key
template<Cryptography::SupportedHashAlgs HashAlg>
CryptoPP::ECDSA<CryptoPP::ECP, HashAlg> Cryptography::Ecdsa::get_decompressed(uint8_t *public_key, uint16_t public_key_len)
{
	typename CryptoPP::ECDSA<CryptoPP::ECP, HashAlg>::PublicKey public_k;
	CryptoPP::ECPPoint point;
	public_k.GetGroupParameters().GetCurve().DecodePoint(point, public_key, public_key_len);
	public_k.SetPublicElement(point);
	return public_k;
}


// generator initializer
// hmacf: hmac function
// pt: plaintext
// pt_len: plaintext length
void Cryptography::Hmac::generator_init(auto hmacf, uint8_t *ct, uint64_t pt_len)
{
	hmacf.CalculateDigest(mac, ct, pt_len);
}

// mac member has to be initialized before calling
bool Cryptography::Hmac::verifier_init(auto hmacf, uint8_t *ct, uint64_t len, uint8_t *hmac)
{
	hmacf.CalculateDigest(mac, ct, len);

    // Compare the calculated HMAC with the expected HMAC
    bool verified = memcmp(mac, hmac, protocol.mac_size) == 0;
	return verified;
}

Cryptography::Hmac::Hmac(ProtocolData &protocol, uint8_t *key) : protocol(protocol)
{
	this->key = key;
	mac = new uint8_t[protocol.mac_size];
}

Cryptography::Hmac::~Hmac()
{
	delete[] mac;
}

// get mac
uint8_t *Cryptography::Hmac::get_mac()
{
	return mac;
}

// get if verified
bool Cryptography::Hmac::is_verified()
{
	return verified;
}

// generate the HMAC code
void Cryptography::Hmac::generate(uint8_t *ct, uint64_t len)
{
	if(protocol.hash == SHA256) {
		CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, protocol.key_size);
		generator_init(hmac, ct, len);
	} else if(protocol.hash == SHA512) {
		CryptoPP::HMAC<CryptoPP::SHA512> hmac(key, protocol.key_size);
		generator_init(hmac, ct, len);
	} else {
		#if DEBUG_MODE
			throw std::runtime_error("Hmac::generate: HASHING_ALGORITHM_NOT_FOUND error. The protocol number is not valid");
		#endif
		error = HASHING_ALGORITHM_NOT_FOUND;

		// default values
		CryptoPP::HMAC<default_hash> hmac(key, protocol.key_size);
		generator_init(hmac, ct, len);
	}
}

// verify the HMAC code
bool Cryptography::Hmac::verify(uint8_t *ct, uint64_t len, uint8_t *mac_code)
{
	if(protocol.hash == SHA256) {
		CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, protocol.key_size);
		verified = verifier_init(hmac, ct, len, mac_code);
	} else if(protocol.hash == SHA512) {
		CryptoPP::HMAC<CryptoPP::SHA512> hmac(key, protocol.key_size);
		verified = verifier_init(hmac, ct, len, mac_code);
	} else {
		#if DEBUG_MODE
			throw std::runtime_error("Hmac::verify: HASHING_ALGORITHM_NOT_FOUND error. The protocol number is not valid");
		#endif
		error = HASHING_ALGORITHM_NOT_FOUND;

		// default values
		CryptoPP::HMAC<default_hash> hmac(key, protocol.key_size);
		verified = verifier_init(hmac, ct, len, mac_code);
	}
	return verified;
}

std::string get_time()
{
    auto time = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(time);
	return std::ctime(&end_time);
}
