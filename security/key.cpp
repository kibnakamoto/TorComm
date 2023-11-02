#include <iostream>
#include <string>
#include <chrono>
#include <cstdlib>
#include <thread>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <cryptopp/chacha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>

// this is for generating the key using a password

// key_value: the value of the key, if you have a key but want to update other aspects, call it
// key_size: size of key, includes 2 byte port key, 32-byte key, and 32-byte pepper
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
void gen_key_exe(uint8_t *key_value=nullptr, uint16_t key_size=68, uint16_t enc_key_size=32, uint16_t pepper_size=32, uint16_t port_key_size=2)
{
	uint8_t *key = new uint8_t[key_size];
	uint8_t *key_to_hash = new uint8_t[64]; // made up of 32-byte pepper and 32-byte password. Hashed then encryptes the key
	uint8_t *pepper = new uint8_t[64]; // copy of pepper
	uint8_t *iv = new uint8_t[12];
	CryptoPP::AutoSeededRandomPool rng;

	// generate key and pepper
	if(key_value == nullptr) {
		rng.GenerateBlock(key, key_size);
	} else {
		memcpy(key, key_value, key_size);
	}
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
	uint8_t *encrypted = new uint8_t[key_size]; // hash of key_to_hash
	CryptoPP::SHA256().CalculateDigest(hash, key_to_hash, 64);
	CryptoPP::ChaCha::Encryption chacha;
	chacha.SetKeyWithIV(hash, 32, iv);
	chacha.ProcessData(encrypted, key, key_size);

	// hash the hash of key_to_hash
	CryptoPP::SHA256().CalculateDigest(hash, hash, 32);


	// generate executable for getting the key
	std::stringstream command;
	command << "gcc -std=c++23 -w -O4 -xc++ -o get_keys.o -c - << EOF";
	command << "\n#include <iostream>";
	command << "\n#include <string>";
	command << "\n#include <cstdlib>";
	command << "\n#include <iomanip>";
	command << "\n#include <chrono>";
	command << "\n#include <thread>";
	command << "\n#include <fstream>";
	command << "\n#include <filesystem>";
	command << "\n#include <cryptopp/chacha.h>";
	command << "\n#include <cryptopp/osrng.h>";
	command << "\n#include <cryptopp/sha.h>";
	command << "\nint main() {";
	command << "\n	uint8_t *encrypted = new uint8_t[" << key_size << "];";
	command << "\n	uint8_t *decrypted = new uint8_t[" << key_size << "];";
	command << "\n	uint8_t *hash_pepper = new uint8_t[64];";
	command << "\n	uint8_t *hash = new uint8_t[32];";
	command << "\n	uint8_t *iv = new uint8_t[12];";
	command << "\n	uint8_t *tmp_hash = new uint8_t[32];";
	command << "\n	uint8_t *tmp_hash2 = new uint8_t[32];";
	command << "\n	uint8_t *correct_hash = new uint8_t[32];";
	command << "\n	std::string password;";

	// copy values
	for(uint16_t i=0;i<32;i++) {
		command << "\n	encrypted[" << i << "] = " << encrypted[i]+0 << ";";
		command << "\n	hash[" << i << "] = " << hash[i]+0 << ";";
		command << "\n	hash_pepper[" << i+32 << "] = " << pepper[i+32]+0 << ";";
		if(i < 29) { // 30,31 not included
			command << "\n	hash_pepper[" << i << "] = " << pepper[i]+0 << ";";
		}
	}

	// add last 2 bytes of encrypted key
	command << "\n	encrypted[32] = " << encrypted[32]+0 << ";";
	command << "\n	encrypted[33] = " << encrypted[33]+0 << ";";

	// copy iv
	for(uint16_t i=0;i<12;i++) {
		command << "\n	iv[" << i << "] = " << iv[i]+0 << ";";
	}

	// ask for password and check if password + the missing 2-3 bytes match the generated ones. Once they're found,
	// hash and compare to hash. Then assign the correct tmp_hash to correct_hash if correct one found
	command << "\n	bool valid=0;";
	command << "\n	CryptoPP::AutoSeededRandomPool rng;";
	command << "\n	uint32_t invalid_count=0;";
	command << "\n	while(true) {";
	command << "\n		std::cout << std::endl << \"Input password: \";";
	command << "\n		std::cin >> password;";
	command << "\n		for(int i=0;i<password.length();i++) {"; // use password in hash_pepper
	command << "\n			hash_pepper[i+32] ^= password[i];";
	command << "\n		}";
	command << "\n		for(uint32_t i=0;i<0xffffff;i++) {"; // guess the 2 missing bytes
	command << "\n			hash_pepper[31] = i & 0xff;"; // guess first byte
	command << "\n			hash_pepper[30] = i >> 16;"; // guess second byte
	command << "\n			hash_pepper[29] = i >> 8;"; // guess second byte
	command << "\n			CryptoPP::SHA256().CalculateDigest(tmp_hash, hash_pepper, 64);";
	command << "\n			CryptoPP::SHA256().CalculateDigest(tmp_hash2, tmp_hash, 32);"; // re-hash and compare
	command << "\n			bool equal = 1;";
	command << "\n			for(uint16_t j=0;j<32;j++) {";
	command << "\n				if(tmp_hash2[j] != hash[j]) {";
	command << "\n					equal = 0;";
	command << "\n				}";
	command << "\n			}";
	command << "\n			if(equal) {valid=true; memcpy(correct_hash, tmp_hash, 32);}"; // if hashes match
	command << "\n		}";
	command << "\n		if(invalid_count != 0) {";
	command << "\n			if (invalid_count%3 == 0 && invalid_count < 7) {"; // if between 3,6 tries made
	command << "\n				std::cout << std::endl << \"wait for 10 seconds, too many tries\";"; // if there was no match
	command << "\n				std::this_thread::sleep_for(std::chrono::seconds(10));";
	command << "\n			} else if (invalid_count%5 == 0) { ";
	command << "\n				std::cout << std::endl << \"wait for 30 seconds, too many tries\";"; // if there was no match
	command << "\n				std::this_thread::sleep_for(std::chrono::seconds(30));";
	command << "\n			}";
	command << "\n		}";
	command << "\n		std::this_thread::sleep_for(std::chrono::seconds(rng.GenerateWord32(1,5)));"; // wait for 3 seconds regardless of match, so the user doesn't know if it is correct or wrong without waiting 3 seconds
	command << "\n		if(!valid) {"; // if wrong password
	command << "\n			invalid_count++;";
	command << "\n			for(int i=0;i<password.length();i++) {"; // remove password from hash_pepper
	command << "\n				hash_pepper[i+32] ^= password[i];";
	command << "\n			}";
	command << "\n			std::cout << std::endl << \"Wrong password, please try again\";"; // if there was no match
	command << "\n			if(invalid_count > 10) {"; // if more than 10 tries made, then it's probably a hacker. So delete data
	// command << "				std::filesystem::remove_all(std::filesystem::current_path);"; // remove everything in directory TODO: uncomment when after testing
	command << "\n			}";
	command << "\n		} else {"; // if correct password
	command << "\n			std::cout << std::endl << \"Correct password.\";";
	command << "\n			CryptoPP::ChaCha::Encryption chacha;"; // decrypt key
	command << "\n			chacha.SetKeyWithIV(correct_hash, 32, iv);";
	command << "\n			chacha.ProcessData(decrypted, encrypted, " << key_size << ");";
	command << "\n			std::ofstream file(\"keys\");"; // create a keys text file and add keys
	command << "\n			for(int i=0;i<" << key_size << ";i++) {"; // create a keys text file and add keys
	command << "\n				file << std::setfill('0') << std::hex << std::setw(2) << decrypted[i]+0;";
	command << "\n			}";
	command << "\n			file << \"\\n\" << std::setfill('0') << std::hex << std::setw(4) << " << enc_key_size << ";";
	command << "\n			file  	    	<< std::setfill('0') << std::hex << std::setw(4) << " << port_key_size << ";";
	command << "\n			file  	    	<< std::setfill('0') << std::hex << std::setw(4) << " << pepper_size << ";";
	command << "\n			file.close();";
	command << "\n			break;";
	command << "\n		}";
	command << "\n	}";

	// set all values in ram to zero
	command << "\n	memset(encrypted, 0, " << key_size << ");";
	command << "\n	memset(decrypted, 0, " << key_size << ");";
	command << "\n	memset(hash_pepper, 0, 64);";
	command << "\n	memset(hash, 0, 32);";
	command << "\n	memset(iv, 0, 12);";
	command << "\n	memset(tmp_hash, 0, 32);";
	command << "\n	memset(tmp_hash2, 0, 32);";
	command << "\n	memset(correct_hash, 0, 32);";

	command << "\n	delete[] encrypted;";
	command << "\n	delete[] decrypted;";
	command << "\n	delete[] hash_pepper;";
	command << "\n	delete[] hash;";
	command << "\n	delete[] iv;";
	command << "\n	delete[] tmp_hash;";
	command << "\n	delete[] tmp_hash2;";
	command << "\n	delete[] correct_hash;";
	command << "}\n";
	command << "EOF";
	std::system(command.str().c_str());
	std::system("g++ get_keys.o -o get_keys -Iinclude -Llib -lcryptopp -lpthread");

	// read get_keys.o into pointer and set to ones
	auto get_keys_o = std::filesystem::current_path()/"get_keys.o";
	if(std::filesystem::exists(get_keys_o)) {
		std::fstream file("get_keys.o", std::ios::binary | std::ios::ate);
		file.seekg(0, std::ios::beg);
		size_t file_size = std::filesystem::file_size("get_keys.o");
		char *obj = new char[file_size];
		file.read(obj, file_size);
		memset(obj, 0xff, file_size); // set to ones
		file.close();
		file.open("get_keys.o", std::fstream::out | std::fstream::trunc);
		file << (const char*)obj; // set file data
		std::filesystem::remove(get_keys_o); // delete file
		file.close();
		delete[] obj;
	}

	// set all data to zero so nothing can be found in ram even if memory address is later found after deallocation
	memset(hash, 0, 32);
	memset(key_to_hash, 0, 64);
	memset(iv, 0, 12);
	memset(key, 0, key_size);
	memset(encrypted, 0, key_size);
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
