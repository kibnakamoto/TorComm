CXX = g++
CXXFLAGS = -std=c++23 -Wall -pedantic -Wextra -O4 -g
CRYPTOPP_FLAGS = -Iinclude -Llib -lcryptopp -lpthread

all:
	${CXX} ${CXXFLAGS} key.cpp -o key ${CRYPTOPP_FLAGS} 

.PHONY: clean
clean:
	rm -rf key
