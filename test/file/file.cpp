/* Test file functions: move_file, delete_file */
#include <iostream>
#include <stdint.h>
#include <string>
#include <chrono>
#include <filesystem>
#include <assert.h>

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
	std::cout << std::endl << "-------------- START FILE TEST --------------";
	std::string n1 = "old.txt";
	std::string n2 = "new.txt";
	bool passed = true; // passed everything

	// create_file
	create_file(n1, "hello world!"); // length:12

	// text file
	std::cout << "speed (test_move): " << test_move(n1, n2).count() << "ns\n";

	// check file:
	bool check_text = get_data(n2) == "hello world!";
	if(check_text) {
		std::cout << std::endl << "PASSED - File management (move_file)";
	} else {
		passed = false;
		std::cout << std::endl << "FAILED - File management (move_file)";
	}

	// test image
	n1 = "image.png"; // whenever testing, copy original.png onto image.png
	n2 = "new.png";

	// image file
	std::cout << "\nspeed (test_move) image: " << test_move(n1, n2).count() << "ns\n";

	// check file:
	bool check_image = get_data(n2) == get_data("original.png");
	if(check_image) {
		std::cout << std::endl << "PASSED - Image File management (move_file)";
	} else {
		passed = false;
		std::cout << std::endl << "FAILED - Image File management (move_file)";
	}
	// copy image.png back
	Cryptography::copy_file("original.png", n1);

	// delete file:
	std::cout << "\nspeed (test_delete): " << test_delete("new.txt").count() << "ns\n";
	std::cout << "\nspeed (test_delete) image: " << test_delete(n2).count() << "ns\n";
	std::cout << std::endl << std::endl << "FILE TEST: " << (passed ? "PASSED WHOLE TEST" : "FAILED SOME/ALL");

	assert(check_text);
	assert(check_image);

	std::cout << std::endl << std::endl << "--------------- END FILE TEST ---------------\n";
	return 0;
}
