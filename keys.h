#include <string>
#include <stdint.h>

void new_port_ip_key();

void get_port_ip_key(uint8_t *key);

std::string to_hex_str(uint8_t *ptr, uint16_t ptr_len);

uint16_t hex_str_to(std::string str, uint8_t *ptr);

void parse_ipv4(uint8_t *out, std::string ip);

void parse_ipv6(uint8_t *out, std::string ip);

std::string get_ipv6();

void init_configure_json(std::string config_path);

class Configure;
