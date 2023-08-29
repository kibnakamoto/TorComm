CXX = g++
CXX_FLAGS = -g -std=c++20 -Wall -pedantic -Wextra -O4
CRYPTOPP_FLAGS =   -Iinclude -Llib -lcryptopp -lpthread
JSON_FLAGS = -ljsoncpp
CURL_FLAGS = -lcurl
EXEC ?= torcomm
TORCOMM ?= torcomm.cpp
GENKEY = keys.cpp
GENKEY_EXEC = genkeys
OBJS=n

${EXEC}: ${TORCOMM}
	${CXX} ${CXXFLAGS} ${TORCOMM} -o ${EXEC}

${GENKEY_EXEC}: ${GENKEY}
	${CXX} ${CXXFLAGS} ${GENKEY} -o ${GENKEY_EXEC} ${CRYPTOPP_FLAGS} ${JSON_FLAGS} ${CURL_FLAGS}

all: ${TORCOMM}
	${CXX} ${CXXFLAGS} ${TORCOMM} -o ${EXEC}
	${CXX} ${CXXFLAGS} ${GENKEY} -o ${GENKEY_EXEC} ${CRYPTOPP_FLAGS} ${JSON_FLAGS} ${CURL_FLAGS}

clean:
	rm -rf ${OBJS}

