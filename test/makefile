CXX = g++
CXXFLAGS = -std=c++23 -Wall -pedantic -Wextra -O4 -g
EXEC = block/block crypto/crypto file/file misc/pad
OBJS_CLEAN = block/*.o crypto/*.o file/*.o misc/*.o
OBJS = block/blocked.o crypto/crypto.o file/file.o misc/padding.o
MAIN = test.cpp

# block: test blocking an ip address
# crypto: test cryptography
# file: test file management
# misc: certain functions used in code (cryptographic padding)

all: ${OBJS}
	${MAKE} -C ../ debug
	${MAKE} -C block/
	${MAKE} -C crypto/
	${MAKE} -C file/
	${MAKE} -C misc/
	${CXX} ${CXXFLAGS} test.cpp -o test

.PHONY: clean
clean:
	rm -rf ${EXEC} ${OBJS_CLEAN} test.txt

