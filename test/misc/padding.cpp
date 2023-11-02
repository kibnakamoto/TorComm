/******************************************************************************

Welcome to GDB Online.
GDB online is an online compiler and debugger tool for C, C++, Python, Java, PHP, Ruby, Perl,
C#, OCaml, VB, Swift, Pascal, Fortran, Haskell, Objective-C, Assembly, HTML, CSS, JS, SQLite, Prolog.
Code, Compile, Run and Debug online from anywhere in world.

*******************************************************************************/
#include <iostream>
#include <cstring>

// test padding functions

struct Protocol
{
    uint16_t block_size = 16; 
};
auto protocol = Protocol();

uint8_t *pad(uint8_t *data, uint16_t &length)
{
    uint8_t *dat;
	uint8_t pad_size;
    uint16_t original_length = length;
	uint16_t mod = length % protocol.block_size;
    pad_size = protocol.block_size - mod;
    length += pad_size;
    dat = new uint8_t[length];
    memcpy(&dat[pad_size], data, original_length); // for left to right padding
    // memcpy(dat, data, original_length);				  // for right to left padding (append to end of message)
	dat[0] = pad_size; // last digit of data is length
    delete[] data;
    return dat;
}

// keep the pad size from the original length. delete it accordingly
// to delete:
//		delete[] (data-pad_size);
void unpad(uint8_t *&data, uint16_t &length)
{
    uint8_t pad_size = data[0];
    length -= pad_size;

	// realloc
	uint8_t *new_data = new uint8_t[length];
	memcpy(new_data, &data[pad_size], length);
	delete[] data;
	data = new_data;
}

int main()
{
    uint16_t length = 46;
    uint8_t *data = new uint8_t[length];
    for(int i=0;i<length;i++) {
        data[i] = 97+i;
        std::cout << std::endl << data[i];
    }
    std::cout << std::endl << "padded data:\n";
    
    data = pad(data, length);
    
    for(int i=0;i<length;i++) {
        std::cout << std::endl << data[i]+0;
    }
    std::cout << std::endl << "unpadded data:\n";
    uint16_t pad_size = data[0];
    unpad(data, length);
    for(int i=0;i<length;i++) {
        std::cout << std::endl << data[i]+0;
    }
    std::cout << std::endl << std::endl << "no padding length: " << length;
    std::cout << std::endl << std::endl << "padded length: " << (length+pad_size);
    delete[] (data); // -pad_size must delete this way
    return 0;
}
