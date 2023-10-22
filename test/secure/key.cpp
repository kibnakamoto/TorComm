#include <iostream>
#include <string>
#include <chrono>
#include <cstdlib>
#include <thread>
#include <sstream>
#include <cryptopp/chacha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>

// this is for generating the key using a password

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
void gen_key_exe()
{
	uint8_t *key = new uint8_t[34];
	uint8_t *key_to_hash = new uint8_t[64]; // made up of 32-byte pepper and 32-byte password. Hashed then encryptes the key
	uint8_t *pepper = new uint8_t[64]; // copy of pepper
	uint8_t *iv = new uint8_t[12];
	CryptoPP::AutoSeededRandomPool rng;

	// generate key and pepper
	rng.GenerateBlock(key, 34);
	rng.GenerateBlock(key_to_hash, 64);
	memcpy(pepper, key_to_hash, 64); // make a copy of pepper
	rng.GenerateBlock(iv, 12);
	
	std::string password;

	// set password
	while(true)
	{
			std::cout << std::endl << "enter new password (4-32 characters): ";
			std::cin >> password;
			if(password.length() >= 4 and password.length() <= 32) {
				break;
			} else {
				std::cout << std::endl << "range of password is wrong, make sure the password is between 4-32 characters";
				std::this_thread::sleep_for(std::chrono::seconds(3)); // wait for 3 seconds
			}
	}
	
	// set key_to_hash[32-64] to 32 byte pepper xor password
	for(size_t i=0;i<password.length();i++) {
		key_to_hash[i+32] ^= password[i];
	}

	// hash key_to_hash and use as key to encrypt key
	uint8_t *hash = new uint8_t[32]; // hash of key_to_hash
	uint8_t *encrypted = new uint8_t[34]; // hash of key_to_hash
	CryptoPP::SHA256().CalculateDigest(hash, key_to_hash, 64);
	CryptoPP::ChaCha::Encryption chacha;
	chacha.SetKeyWithIV(hash, 32, iv);
	chacha.ProcessData(encrypted, key, 34);

	// hash the hash of key_to_hash
	CryptoPP::SHA256().CalculateDigest(hash, hash, 32);


	// generate executable for getting the key
	std::stringstream command;
	command << "gcc -std=c++23 -w -O4 -xc++ -o get_keys.o -c - << EOF";
	command << "\n#include <iostream>";
	command << "\n#include <string>";
	command << "\n#include <cstdlib>";
	command << "\n#include <chrono>";
	command << "\n#include <thread>";
	command << "\n#include <cryptopp/chacha.h>";
	command << "\n#include <cryptopp/osrng.h>";
	command << "\n#include <cryptopp/sha.h>";
	command << "\nint main() {";
	command << "	uint8_t *encrypted = new uint8_t[34];";
	command << "	uint8_t *decrypted = new uint8_t[34];";
	command << "	uint8_t *hash_pepper = new uint8_t[64];";
	command << "	uint8_t *hash = new uint8_t[32];";
	command << "	uint8_t *iv = new uint8_t[12];";
	command << "	uint8_t *tmp_hash = new uint8_t[32];";
	command << "	uint8_t *correct_hash = new uint8_t[32];";

	// copy values
	for(uint16_t i=0;i<32;i++) {
		command << "	encrypted[" << i << "] = " << encrypted[i]+0 << ";";
		command << "	hash[" << i << "] = " << hash[i]+0 << ";";
		command << "	hash_pepper[" << i+32 << "] = " << pepper[i+32]+0 << ";";
		if(i < 30) { // 30,31 not included
			command << "	hash_pepper[" << i << "] = " << pepper[i]+0 << ";";
		}
	}

	// copy iv
	for(uint16_t i=0;i<12;i++) {
		command << "	iv[" << i << "] = " << iv[i]+0 << ";";
	}

	// set all values in ram to zero
	command << "	memset(encrypted, 0, 34);";
	command << "	memset(decrypted, 0, 34);";
	command << "	memset(hash_pepper, 0, 64);";
	command << "	memset(hash, 0, 32);";
	command << "	memset(iv, 0, 12);";
	command << "	memset(tmp_hash, 0, 32);";
	command << "	memset(correct_hash, 0, 32);";

	command << "	delete[] encrypted;";
	command << "	delete[] decrypted;";
	command << "	delete[] hash_pepper;";
	command << "	delete[] hash;";
	command << "	delete[] iv;";
	command << "	delete[] tmp_hash;";
	command << "	delete[] correct_hash;";
	command << "}\n";
	command << "EOF";
	std::system(command.str().c_str());

	// set all data to zero so nothing can be found in ram even if memory address is later found after deallocation
	memset(hash, 0, 32);
	memset(key_to_hash, 0, 64);
	memset(iv, 0, 12);
	memset(key, 0, 34);
	memset(encrypted, 0, 34);
	memset(&password[0], 0, password.length());
	memset(pepper, 0, 64);
	memset(&command.str()[0], 0, command.str().length());

	delete[] hash;
	delete[] key_to_hash;
	delete[] key;
	delete[] iv;
	delete[] encrypted;
	delete[] pepper;
}
#pragma GCC diagnostic pop

int main()
{
	gen_key_exe();
	return 0;
}
