/* Test file functions: move_file, delete_file */
#include <iostream>
#include <stdint.h>
#include <string>
#include <chrono>

#include "../../message.h"

auto test_move(std::string from, std::string to)
{
	std::chrono::high_resolution_clock::time_point start = std::chrono::high_resolution_clock::now();
	Cryptography::move_file(from, to);
	std::chrono::high_resolution_clock::time_point end = std::chrono::high_resolution_clock::now();
	return std::chrono::nanoseconds((end-start).count());
}

auto test_delete(std::string path)
{
	std::chrono::high_resolution_clock::time_point start = std::chrono::high_resolution_clock::now();
	Cryptography::delete_file(path);
	std::chrono::high_resolution_clock::time_point end = std::chrono::high_resolution_clock::now();
	return std::chrono::nanoseconds((end-start).count());
}

// create file to test
void create_file(std::string name, std::string content)
{
	std::ofstream file(name);
	file << content;
	file.close();
}

// read file
std::string get_data(std::string name)
{
	std::ifstream file(name);
	std::ostringstream os;
    os << file.rdbuf();
	file.close();
	return os.str();
}

int main()
{
	std::string n1 = "old.txt";
	std::string n2 = "new.txt";

	// create_file
	// create_file(n1, "hello world!"); // length:12

	// text file
	std::cout << "speed (test_move): " << test_move(n1, n2).count() << "ns\n";

	// check file:
	// if(get_data(n2) == "hello world!") {
	// 	std::cout << std::endl << "PASSED - File management (move_file)";
	// } else {
	// 	std::cout << std::endl << "FAILED - File management (move_file)";
	// }

	// test image
	n1 = "image.png";
	n2 = "new.png";

	// image file
	std::cout << "speed (test_move): " << test_move(n1, n2).count() << "ns\n";

	// MANUALLY CHECK IF FILE IS CORRECT


	// std::cout << "speed (test_move): " << test_delete(n2);
	std::cout << std::endl;
	return 0;
}
