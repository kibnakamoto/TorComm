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
	Cryptography::CommunicationProtocol comm_protocol = Cryptography::ECIES_HMAC_AES256_CBC_SHA256;
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
	alice_key.hkdf(alice_x, curve_size, (uint8_t*)"", 0, (uint8_t*)"", 0);

	// ECDH - Bob
	auto bob = bob_key.multiply(alice_key.public_key);
	uint8_t *bob_x = new uint8_t[curve_size];
	bob_key.integer_to_bytes(bob.x, bob_x, curve_size);
	bob_key.hkdf(bob_x, curve_size, (uint8_t*)"", 0, (uint8_t*)"", 0);

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
	std::string plaintext = "hello world!";
	// 3. Test Cipher

	// 4. Test HMAC
	// 5. Test Decipher
	// 6. Test ECDSA (Not Version 1.0)
	std::cout << std::endl;
	return 0;
}
