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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
void gen_key_exe(uint16_t key_size=34)
{
	uint8_t *key = new uint8_t[key_size];
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
	command << "\n#include <fstream>";
	command << "\n#include <filesystem>";
	command << "\n#include <cryptopp/chacha.h>";
	command << "\n#include <cryptopp/osrng.h>";
	command << "\n#include <cryptopp/sha.h>";
	command << "\nint main() {";
	command << "	uint8_t *encrypted = new uint8_t[" << key_size << "];";
	command << "	uint8_t *decrypted = new uint8_t[" << key_size << "];";
	command << "	uint8_t *hash_pepper = new uint8_t[64];";
	command << "	uint8_t *hash = new uint8_t[32];";
	command << "	uint8_t *iv = new uint8_t[12];";
	command << "	uint8_t *tmp_hash = new uint8_t[32];";
	command << "	uint8_t *tmp_hash2 = new uint8_t[32];";
	command << "	uint8_t *correct_hash = new uint8_t[32];";
	command << "	std::string password;";

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

	// ask for password and check if password + the missing 2-3 bytes match the generated ones. Once they're found,
	// hash and compare to hash. Then assign the correct tmp_hash to correct_hash if correct one found
	command << "	bool valid=0;";
	command << "	uint16_t valid30=256;";
	command << "	uint16_t valid31=256;";
	command << "	CryptoPP::AutoSeededRandomPool rng;";
	command << "	uint32_t invalid_count=0;";
	command << "	while(true) {";
	command << "		std::cout << std::endl << \"Input password: \";";
	command << "		std::cin >> password;";
	command << "		for(int i=0;i<password.length();i++) {"; // use password in hash_pepper
	command << "			hash_pepper[i+32] ^= password[i];";
	command << "		}";
	command << "		for(uint16_t i=0;i<0xffff;i++) {"; // guess the 2 missing bytes
	command << "			hash_pepper[31] = i >> 8;"; // guess first byte
	command << "			hash_pepper[30] = i & 0xff;"; // guess second byte
	command << "			CryptoPP::SHA256().CalculateDigest(tmp_hash, hash_pepper, 64);";
	command << "			CryptoPP::SHA256().CalculateDigest(tmp_hash2, tmp_hash, 32);"; // re-hash and compare
	command << "			bool equal = 1;";
	command << "			for(uint16_t j=0;i<32;j++) {";
	command << "				if(tmp_hash2[j] != hash[j]) {";
	command << "					equal = 0;";
	command << "				}";
	command << "			}";
	command << "			if(equal) {valid30 = hash_pepper[30]; valid31 = hash_pepper[31]; memcpy(correct_hash, tmp_hash, 32);}"; // if hashes match
	command << "		}";
	command << "		if (invalid_count%3 == 0 && invalid_count < 13) {"; // if between 3,6 tries made
	command << "			std::cout << std::endl << \"wait for 10 seconds, too many tries\";"; // if there was no match
	command << "			std::this_thread::sleep_for(std::chrono::seconds(10));";
	command << "		} else if (invalid_count%5 == 0 && invalid_count > 13) { ";
	command << "			std::cout << std::endl << \"wait for 30 seconds, too many tries\";"; // if there was no match
	command << "			std::this_thread::sleep_for(std::chrono::seconds(30));";
	command << "		}";
	command << "		std::this_thread::sleep_for(std::chrono::seconds(rng.GenerateWord32(1,5)));"; // wait for 3 seconds regardless of match, so the user doesn't know if it is correct or wrong without waiting 3 seconds
	command << "		if(valid30 == 256) {"; // if wrong password
	command << "			invalid_count++;";
	command << "			std::cout << std::endl << \"Wrong password, please try again\";"; // if there was no match
	command << "			if(invalid_count > 20) {"; // if more than 20 tries made, then it's probably a hacker. So delete data
	// command << "				std::filesystem::remove_all(std::filesystem::current_path);"; // remove everything in directory TODO: uncomment when after testing
	command << "			}";
	command << "		} else {"; // if correct password
	command << "			std::cout << std::endl << \"Correct password.\";";
	command << "			CryptoPP::ChaCha::Encryption chacha;"; // decrypt key
	command << "			chacha.SetKeyWithIV(correct_hash, 32, iv);";
	command << "			chacha.ProcessData(decrypted, encrypted, " << key_size << ");";
	command << "			std::ofstream file(\"keys\");"; // create a keys text file and add keys
	command << "			for(int i=0;i<" << key_size << ";i++) {"; // create a keys text file and add keys
	command << "				file << std::setfill('0') << std::setw(2) << decrypted[i]+0;";
	command << "			}";
	command << "			file.close();";
	command << "			break;";
	command << "		}";
	command << "	}";

	// set all values in ram to zero
	command << "	memset(encrypted, 0, " << key_size << ");";
	command << "	memset(decrypted, 0, " << key_size << ");";
	command << "	memset(hash_pepper, 0, 64);";
	command << "	memset(hash, 0, 32);";
	command << "	memset(iv, 0, 12);";
	command << "	memset(tmp_hash, 0, 32);";
	command << "	memset(tmp_hash2, 0, 32);";
	command << "	memset(correct_hash, 0, 32);";

	command << "	delete[] encrypted;";
	command << "	delete[] decrypted;";
	command << "	delete[] hash_pepper;";
	command << "	delete[] hash;";
	command << "	delete[] iv;";
	command << "	delete[] tmp_hash;";
	command << "	delete[] tmp_hash2;";
	command << "	delete[] correct_hash;";
	command << "}\n";
	command << "EOF && g++ get_keys.o -o get_keys";
	std::cout << std::endl << command.str();
	std::system(command.str().c_str());

	// read get_keys.o into pointer and set to zero
	auto get_keys_o = std::filesystem::current_path()/"get_keys.o";
	if(std::filesystem::exists(get_keys_o)) {
		std::fstream file("get_keys.o", std::ios::binary | std::ios::ate);
		file.seekg(0, std::ios::beg);
		size_t file_size = file.tellg();
		char *obj = new char[file_size];
		file.read(obj, file_size);
		memset(obj, 0, file_size); // set to zero
		file.close();
		file.open("get_keys_o", std::fstream::out | std::fstream::trunc);
		file << (std::string)obj; // zero file
		std::filesystem::remove(get_keys_o); // delete file
		file.close();
		delete[] obj;
	}

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
