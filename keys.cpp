#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>

#include "keys.h"
#include "settings.h"

#include <curl/curl.h>

#include <boost/asio/ip/address_v6.hpp>

#include <cryptopp/config_int.h>
#include <cryptopp/chacha.h>
#include <cryptopp/osrng.h>

// Generate keys, and IVs for encrypting ports and IPs in configure.json in all sessions
// encrypt using ChaCha20 because it is a stream cipher, encrypt port and ip using private key

#define ZERO_IP "0000:0000:0000:0000:0000:0000:0000:0000"
#define DEFAULT_PORT 8000
#define PORT_TOR 9005

// Before writing to file, make sure to ask user to backup all keys before replacing
// Make sure to decrypt all IPs and ports before replacing file
// Generate new key in keys.txt file
void new_port_ip_key(Settings settings=global_settings)
{
	std::ofstream file;
    CryptoPP::AutoSeededRandomPool rng;

	file.open(settings.keys, std::ios_base::out);

	uint8_t *k = new uint8_t[32];
	rng.GenerateBlock(k, 32);
	for(uint8_t i=0;i<32;i++) {
		file << k[i]+0;
		if(i !=31)
			file << ".";
	}
}

// read key from keys.txt file
void get_port_ip_key(uint8_t *key, std::string keys_path=global_settings.keys)
{
	std::ifstream keys_file(keys_path);
	std::string keys;
	std::getline(keys_file, keys);
	size_t keys_dot = keys_dot = keys.find('.');
	
	uint8_t i=0;
	while ((keys_dot = keys.find('.')) != std::string::npos)
	{
		uint8_t byte = std::stoi(keys.substr(0, keys_dot));
		key[i] = byte;

	    keys.erase(0, keys_dot + 1);
		i++;
	}
	key[31] = std::stoi(keys);
}

std::string to_hex_str(uint8_t *ptr, uint16_t ptr_len)
{
		std::stringstream ss;
		for(uint16_t i=0;i<ptr_len;i++) {
			ss << std::hex << std::setfill('0') << std::setw(2) << ptr[i]+0;
		}
		return ss.str();
}

// hex string to uint8_t*
// hex string must be padded and length should be a multiple of 2.
uint16_t hex_str_to(std::string str, uint8_t *ptr)
{
	uint16_t len = str.length()/2;
	for(uint16_t i=0;i<len;i++) {
		ptr[i] = std::strtol(str.substr(i*2, 2).c_str(), NULL, 16);
	}
	return len;
}

void parse_ipv4(uint8_t *out, std::string ip)
{
	// assign ip_key
	size_t keys_dot;
	uint8_t i=0;
	while ((keys_dot = ip.find('.')) != std::string::npos)
	{
		uint8_t byte = std::stoi(ip.substr(0, keys_dot));
		out[i] = byte;
	
	    ip.erase(0, keys_dot + 1);
		i++;
	}
	out[3] = std::stoi(ip);
}

void parse_ipv6(uint8_t *out, std::string ip)
{
	boost::asio::ip::address_v6 adr = boost::asio::ip::make_address_v6(ip);
	std::array<uint8_t, 16> tmp = adr.to_bytes();
	for(uint8_t i=0;i<16;i++) {out[i] = tmp[i];}
}

// helper function
static size_t write_call_back(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// get public ipv6 address
std::string get_ipv6()
{
	 CURL *curl;
   CURLcode res;
   std::string ret;

   curl = curl_easy_init();
   if(curl) {
     curl_easy_setopt(curl, CURLOPT_URL, "https://myexternalip.com/raw");
     curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_call_back);
	 curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ret);
     res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
   }
   return ret;
}

// default configure.json file don't forget to update IVs
// generate file in new session
void init_configure_json(std::string config_path)
{
	CryptoPP::AutoSeededRandomPool rng;
	Json::Value json_conf;
	std::ofstream file;

	file.open(config_path, std::ios_base::out | std::ofstream::trunc);

	json_conf["0"] = ZERO_IP;
	json_conf["PUBLIC"] = get_ipv6();
	json_conf["PORT"] = DEFAULT_PORT;
	json_conf["TOR PORT"] = PORT_TOR;

	// generate and set IVs
	uint8_t *ptr = new uint8_t[CryptoPP::ChaCha::IV_LENGTH];
	rng.GenerateBlock(ptr, CryptoPP::ChaCha::IV_LENGTH); // generate port IV
	json_conf["IV"]["PORT"] = to_hex_str(ptr, CryptoPP::ChaCha::IV_LENGTH);
	rng.GenerateBlock(ptr, CryptoPP::ChaCha::IV_LENGTH); // generate tor port IV
	json_conf["IV"]["TOR PORT"] = to_hex_str(ptr, CryptoPP::ChaCha::IV_LENGTH);
	rng.GenerateBlock(ptr, CryptoPP::ChaCha::IV_LENGTH); // generate public ip IV
	json_conf["IV"]["PUBLIC"] = to_hex_str(ptr, CryptoPP::ChaCha::IV_LENGTH);
	rng.GenerateBlock(ptr, CryptoPP::ChaCha::IV_LENGTH); // generate public ip 1 IV
	json_conf["IV"]["0"] = to_hex_str(ptr, CryptoPP::ChaCha::IV_LENGTH);
	
	file << json_conf;
	delete[] ptr;
}

// parse configure.json in sessions, modify config for updating values
class Configure
{
	public:
		uint16_t port;
		uint16_t tor_port;
		std::string public_ip;
		std::string *other_public_ips; // other ips
		uint32_t node_count;
		Json::Value config;
		std::string config_path;
		uint8_t **IVs; // IVs for all ips and ports in configuration.json
		enum IV {PORT, TOR_PORT, PUBLIC, PUBLIC_1}; // indexing of iv

		Configure(std::string configpath)
		{
			config_path = configpath;
			std::fstream file(config_path);
			file >> config;
			node_count = get_node_count();

			IVs = new uint8_t*[node_count+4];
			for(uint8_t i=0;i<node_count+4;i++) IVs[i] = new uint8_t[CryptoPP::ChaCha::IV_LENGTH];
			other_public_ips = new std::string[node_count];
			get_values();
		}

		uint32_t get_node_count()
		{
			uint32_t i=0;
			while (config.isMember(std::to_string(i))) i++;
			return i;
		}

		// destructor
		~Configure()
		{
			for(uint8_t i=0;i<node_count+4;i++) delete[] IVs[i];
			delete[] IVs;
			delete[] other_public_ips;
		}

		void get_values()
		{
			//std::cout << std::endl << to_hex_str(*IVs, CryptoPP::ChaCha::IV_LENGTH) << std::endl;
			port = config["PORT"].asUInt();
			tor_port = config["TOR PORT"].asUInt();
			public_ip = config["PUBLIC"].asString();
			for(uint32_t i=0;i<node_count;i++) {
				other_public_ips[i] = config[std::to_string(i)].asString();
			}
			
			// get IVs
			hex_str_to(config["IV"]["PORT"].asString(), IVs[PORT]);
			hex_str_to(config["IV"]["TOR PORT"].asString(), IVs[TOR_PORT]);
			hex_str_to(config["IV"]["PUBLIC"].asString(), IVs[PUBLIC]);
			for(uint32_t i=0;i<node_count;i++) {
				hex_str_to(config["IV"][std::to_string(i)].asString(), IVs[i+PUBLIC_1]);
			}
		}

		// reset config to file
		void reset()
		{
			std::fstream file(config_path);
			file >> config;
		}

		// write member values back
		void write_values()
		{
			config["PORT"]      = port;
			config["TOR PORT"]  = tor_port;
			config["PUBLIC"]    = public_ip;
			for(uint32_t i=0;i<node_count;i++) {
				config[std::to_string(i)] = other_public_ips[i];
			}

			// IVs
			config["IV"]["PORT"] = to_hex_str(IVs[PORT], CryptoPP::ChaCha::IV_LENGTH);
			config["IV"]["TOR PORT"] = to_hex_str(IVs[TOR_PORT], CryptoPP::ChaCha::IV_LENGTH);
			config["IV"]["PUBLIC"] = to_hex_str(IVs[PUBLIC], CryptoPP::ChaCha::IV_LENGTH);
			for(uint32_t i=0;i<node_count;i++) {
				config["IV"][std::to_string(i)] = to_hex_str(IVs[i+PUBLIC_1], CryptoPP::ChaCha::IV_LENGTH);
			}
		}

		// call write_values() to assign object members to config then call this function to write to file
		void write_to_file()
		{
			// write back to file
			std::fstream file(config_path, std::ios_base::out);
			file << config;
		}

		// generate 6 new IVs for encrypting config members
		// IVs are a nonce so save them in config and only use them once
		void new_ivs()
		{
			CryptoPP::AutoSeededRandomPool rng;
			rng.GenerateBlock((IVs[PORT]), CryptoPP::ChaCha::IV_LENGTH); // generate port IV
			rng.GenerateBlock((IVs[TOR_PORT]), CryptoPP::ChaCha::IV_LENGTH); // generate tor port IV
			rng.GenerateBlock((IVs[PUBLIC]), CryptoPP::ChaCha::IV_LENGTH); // generate public ip IV
			rng.GenerateBlock((IVs[PUBLIC_1]), CryptoPP::ChaCha::IV_LENGTH); // generate public ip 1 IV
			
			// set config
			config["IV"]["PORT"] = to_hex_str(IVs[PORT], CryptoPP::ChaCha::IV_LENGTH);
			config["IV"]["TOR PORT"] = to_hex_str(IVs[TOR_PORT], CryptoPP::ChaCha::IV_LENGTH);
			config["IV"]["PUBLIC"] = to_hex_str(IVs[PUBLIC], CryptoPP::ChaCha::IV_LENGTH);
			for(uint32_t i=0;i<node_count;i++) {
				config["IV"][std::to_string(i)] = to_hex_str(IVs[i+PUBLIC_1], CryptoPP::ChaCha::IV_LENGTH);
			}
		}

		// decrypt all
		void decrypt(std::string keys_path=global_settings.keys)
		{
			process(keys_path);
		}

		void encrypt(std::string keys_path=global_settings.keys)
		{
			process(keys_path);
			write_to_file(); // if encrypt, write to file
		}

	protected:

		// encrypt/decrypt configure.json values in every session
		// config_path: the path of configure.json
		// keys_path: path of keys.txt
		// return config, call config.write_to_file() to save values
		void process(std::string keys_path=global_settings.keys)
		{
			uint8_t *key = new uint8_t[32];
			get_port_ip_key(key, keys_path); // assign key from file to array
		
			// encrypt all values in configure
			CryptoPP::ChaCha::Encryption chacha;
			
		
			// encrypt port
			uint8_t *str_port = new uint8_t[2];
			uint8_t port_len;
		
			 // convert port to bytearray
			if (port > 0xff) {
				str_port[0] = (uint8_t)(port >> 8);
				str_port[1] = (uint8_t)port;
				port_len = 2;
			} else {
				*str_port = (uint8_t)port;
				port_len = 1;
			}
			// encrypt port
			uint8_t *ct = new uint8_t[port_len];
			chacha.SetKeyWithIV(key, 32, IVs[PORT]); // 256-bit chacha20 encryption key
			chacha.ProcessData(ct, (const CryptoPP::byte *)str_port, port_len);
			port = ((uint16_t)ct[0] << 8) | ct[1];
			
			// encrypt/decrypt tor port
		
			 // convert tor port to bytearray
			if (tor_port > 0xff) {
				str_port[0] = (uint8_t)(tor_port >> 8);
				str_port[1] = (uint8_t)tor_port;
				port_len = 2;
			} else {
				*str_port = (uint8_t)tor_port;
				port_len = 1;
			}
			delete[] ct;
			ct = new uint8_t[port_len];
		
		
			chacha.SetKeyWithIV(key, 32, IVs[TOR_PORT]); // 256-bit chacha20 encryption key
			chacha.ProcessData(ct, (const CryptoPP::byte *)str_port, port_len);
			tor_port = ((uint16_t)ct[0] << 8) | ct[1];
			delete[] str_port;
			delete[] ct;
		
			// encrypt/decrypt public ip, all IPs are encrypted byte by byte. the dots aren't encrypted
			ct = new uint8_t[16];
			uint8_t *ip = new uint8_t[16];
			parse_ipv6(ip, public_ip);
			chacha.SetKeyWithIV(key, 32, IVs[PUBLIC]); // 256-bit chacha20 encryption key
			public_ip = "";
			for(uint8_t i=0;i<8;i++) {
				std::stringstream ss;
				chacha.ProcessData(&ct[i*2], &ip[i*2], 1);
				chacha.ProcessData(&ct[i*2+1], &ip[i*2+1], 1);
				//ss << std::hex << ((uint16_t)ct[i*2] << 8 | ct[i*2+1]);
				ss << std::setfill('0') << std::setw(2) << std::hex << ct[i*2]+0; 
				ss << std::setfill('0') << std::setw(2) << std::hex << ct[i*2+1]+0;
				public_ip += ss.str();
				
				if(i != 7) public_ip += ":";
			}
		
			// on other devices
		
			// encrypt/decrypt public ip 1 (other device)
			for(uint32_t n=0;n<node_count;n++) {
				parse_ipv6(ip, other_public_ips[n]);
				chacha.SetKeyWithIV(key, 32, IVs[n+PUBLIC_1]); // 256-bit chacha20 encryption key
				other_public_ips[n] = "";
				for(uint8_t i=0;i<8;i++) {
					std::stringstream ss;
					chacha.ProcessData(&ct[i*2], &ip[i*2], 1);
					chacha.ProcessData(&ct[i*2+1], &ip[i*2+1], 1);
					//ss << std::hex << ((uint16_t)ct[i*2] << 8 | ct[i*2+1]);
					ss << std::setfill('0') << std::setw(2) << std::hex << ct[i*2]+0; 
					ss << std::setfill('0') << std::setw(2) << std::hex << ct[i*2+1]+0;
					other_public_ips[n] += ss.str();
					if(i != 7) other_public_ips[n] += ":";
				}
			}
		
			write_values();
			delete[] ip;
			delete[] key;
			delete[] ct;
		}
};

int main()
{
	//init_configure_json("./configure.json");
	Configure config = Configure("./configure.json");
	config.encrypt();
	return 0;
}
