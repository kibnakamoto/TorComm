#include <string>
#include <stdint.h>
#include <iomanip>

#include <jsoncpp/json/json.h>

void new_port_ip_key();

void get_port_ip_key(uint8_t *key);

std::string to_hex_str(uint8_t *ptr, uint16_t ptr_len);

// convert any unsigned num to hex-string
std::string to_hex_str(auto num)
{
	std::stringstream ss;
	if constexpr(sizeof(num) == 1)
		ss << std::hex << std::setfill('0') << std::setw(2) << num+0;
	else
		ss << std::hex << std::setfill('0') << std::setw(sizeof(num)<<1) << num;
	return ss.str();
}

// convert hex-string to any unsigned num
void hex_str_to(std::string num, auto &out)
{
	std::stringstream ss;
	ss << num;
	ss >> out;
}

uint16_t hex_str_to(std::string str, uint8_t *ptr);

void parse_ipv4(uint8_t *out, std::string ip);

void parse_ipv6(uint8_t *out, std::string ip);

std::string get_ipv6();

void init_configure_json(std::string config_path);


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

		Configure(std::string configpath);

		// Configure to json value
		Configure(std::string configpath, Json::Value _config);

		uint32_t get_node_count();

		// destructor
		~Configure();

		// assign variables to config
		void get_values();

		// reset config to file
		void reset();

		// write member values back
		void write_values();

		// call write_values() to assign object members to config then call this function to write to file
		void write_to_file();

		// generate 6 new IVs for encrypting config members
		// IVs are a nonce so save them in config and only use them once
		void new_ivs();

		// decrypt all
		void decrypt(std::string keys_path);

		void encrypt(std::string keys_path);

	protected:

		// encrypt/decrypt configure.json values in every session
		// config_path: the path of configure.json
		// keys_path: path of keys.txt
		// return config, call config.write_to_file() to save values
		void process(std::string keys_path);
};
