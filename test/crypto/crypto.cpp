#include <cryptopp/modes.h>
#include <iostream>
#include <stdint.h>
#include <string>
#include <fstream>
#include <cassert>
#include <iomanip>
#include <sstream>

#include "../../message.h"

/* Testing Cryptography */

std::string hex(uint8_t *arr, uint16_t len)
{
	std::stringstream ss;
	for(uint16_t i=0;i<len;i++) {
		ss << std::hex << std::setfill('0') << std::setw(2) << arr[i]+0;
	}
	ss << std::endl;
	return ss.str();
}

std::string hex(CryptoPP::Integer integer)
{
	std::stringstream ss;
	ss << std::hex << integer;
	return ss.str();
}

int main()
{
	// 1. Test ProtocolData
	Cryptography::Curves curve = Cryptography::SECP256K1;
	Cryptography::CommunicationProtocol comm_protocol = Cryptography::ECIES_HMAC_AES256_CBC_SHA512;
	uint8_t protocol = (uint8_t)comm_protocol + curve;
	std::cout << std::endl << "protocol number: " << protocol+0 << std::endl;
	Cryptography::ProtocolData protocold(protocol); // initialize
	assert(protocold.error == NO_ERROR); // check if there are any errors

	// 2. Test Key
	// Create Alice's key
	Cryptography::Key alice_key(protocold);
	assert(alice_key.error == NO_ERROR);
	std::cout << "Alice\'s Private Key: " << hex(alice_key.private_key);
	std::cout << "\nAlice\'s public key: (" << hex(alice_key.public_key.x) << ", "
			  << hex(alice_key.public_key.y) << ")";

	// Create Bob's key
	uint16_t curve_size = get_curve_size(protocold.curve);
	Cryptography::Key bob_key(protocold);
	assert(bob_key.error == NO_ERROR);
	std::cout << "\n\nBob\'s Private Key: " << hex(bob_key.private_key);
	std::cout << "\nBob\'s public key: (" << hex(bob_key.public_key.x) << ", "
			  << hex(bob_key.public_key.y) << ")";

	// ECDH - Alice
	auto alice = alice_key.multiply(bob_key.public_key);
	uint8_t *alice_x = new uint8_t[curve_size];
	alice_key.integer_to_bytes(alice.x, alice_x, curve_size);
	alice_key.hkdf(alice_x, curve_size, (uint8_t*)"", 0, (uint8_t*)"", 0); // HKDF

	// ECDH - Bob
	auto bob = bob_key.multiply(alice_key.public_key);
	uint8_t *bob_x = new uint8_t[curve_size];
	bob_key.integer_to_bytes(bob.x, bob_x, curve_size);
	bob_key.hkdf(bob_x, curve_size, (uint8_t*)"", 0, (uint8_t*)"", 0); // HKDF

	std::cout << "\n\nAlice\'s Shared Secret: (" << hex(alice.x) << "," << hex(alice.y) << ")";
	std::cout << "\nBob\'s Shared Secret: (" << hex(bob.x) << "," << hex(bob.y) << ")";

	std::string alice_k = hex(alice_key.key, protocold.key_size);
	std::string bob_k = hex(bob_key.key, protocold.key_size);
	std::cout << "\n\nAlice\'s symmetric Key: " << alice_k;
	std::cout << "\nBob\'s symmetric Key: " << bob_k;

	if(alice_k == bob_k) {
		std::cout << std::endl << "PASSED - ALICE KEY = BOB KEY";
	} else {
		std::cout << std::endl << "FAILED - ALICE KEY != BOB KEY";
	}
	
	delete[] alice_x;
	delete[] bob_x;
	std::string plaintext = "hello world!"; // length: 12
	uint16_t pt_len = plaintext.length();
	char *pt = new char[pt_len];
	memcpy(pt, plaintext.c_str(), pt_len);

	uint8_t *iv = protocold.generate_iv();
	uint8_t *key = alice_key.key;

	// 3. Test Cipher
	Cryptography::Cipher cipher(protocold, key);
	pt = cipher.pad(pt, pt_len);
	std::cout << "\n\n\nplaintext: " << plaintext;
	std::cout << "\npadded plaintext: " << hex((uint8_t*)pt, pt_len);
	assert(pt_len%16 == 0); // assert that plaintext is in 16-byte segments
	std::cout << "\niv: " << hex(iv, protocold.iv_size);
	
	// encrypt
	uint32_t ct_len = pt_len<<(protocold.ct_size/protocold.block_size-1);
	uint8_t *ct = new uint8_t[ct_len];
	auto cipherf = protocold.get_cipher();
	cipher.assign_iv(iv);
	uint8_t *plain = cipher.to_uint8_ptr(pt);
	cipher.encrypt(plain, pt_len, ct, ct_len);
	std::cout << "\nciphertext: " << hex(ct, ct_len);

	// 4. Test Decipher
	Cryptography::Decipher decipher(protocold, key);
	decipher.assign_iv(iv);
	uint32_t decrypted_len = ct_len>>(protocold.ct_size/protocold.block_size-1);
	uint8_t *decrypted = new uint8_t[decrypted_len];
	decipher.decrypt(ct, ct_len, decrypted, decrypted_len);
	std::cout << "\ndecrypted: " << hex(decrypted, decrypted_len);

	uint8_t pad_size = decipher.unpad(decrypted, decrypted_len);
	std::string str;
	str = reinterpret_cast<char*>(decrypted);
	std::cout << "\nDecrypted Text: " << str;

	if(str == plaintext) {
		std::cout << std::endl << "PASSED - BOB PLAINTEXT = ALICE PLAINTEXT";
	} else {
		std::cout << std::endl << "FAILED - BOB PLAINTEXT != ALICE PLAINTEXT";
	}

	// 5. Test HMAC
	Cryptography::Hmac hmac(protocold, key);

	// Alice generates the hmac
	hmac.generate(&plain[pad_size], (uint64_t)pt_len-pad_size); // generate hmac for text without padding
	std::cout << "\nAlice HMAC: " << hex(hmac.get_mac(), protocold.mac_size);
	uint8_t *alice_mac = new uint8_t[protocold.mac_size];
	memcpy(alice_mac, hmac.get_mac(), protocold.mac_size);

	// Bob verifies the hmac
	hmac.verify(decrypted, decrypted_len, alice_mac);
	std::cout << "\nBob HMAC:   " << hex(hmac.get_mac(), protocold.mac_size);

	if(hmac.is_verified()) {
		std::cout << std::endl << "PASSED - BOB VERIFIED HMAC";
	} else {
		std::cout << std::endl << "FAILED - BOB COULDN\'T VERIFY HMAC";
	}

	// 6. Test ECDSA (Not Version 1.0)

	std::cout << std::endl;
	delete[] alice_mac;
	delete[] iv;
	delete[] pt;
	delete[] ct;
	return 0;
}
