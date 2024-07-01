#include <iostream>
#include <fstream>
#include <stdint.h>

static bool check(char *data, uint32_t n, char check_if)
{
	for(uint32_t i=0;i<n;i++) {
		if(data[i] == check_if) return 1;
	}
	return 0;
}

int main()
{
	// run blocking, cryptography, and file management tests
	system("cd block && ./block");
	system("cd crypto && ./crypto");
	system("cd file && ./file");

	std::ifstream file("test.txt");
	char data[3];
	file.read(data, 3);
	bool one = check(data, 3, '1'), two = check(data, 3, '2'), three = check(data, 3, '3');
	if(one && two && three) {
		std::cout << "--- ALL TESTS PASSED SUCCESSFULLY ---";
	} else {
		if(!one) std::cout << "FAILED BLOCK TEST";
		if(!two) std::cout << "FAILED CRYPTO TEST";
		if(!three) std::cout << "FAILED FILE TEST";
	}

	return 0;
}
