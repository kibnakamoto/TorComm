CXX = g++
CXX_FLAGS = -g -std=c++20 -Wall -pedantic -Wextra -O4
CRYPTOPP_FLAGS =   -Iinclude -Llib -lcryptopp -lpthread
JSON_FLAGS = -ljsoncpp
CURL_FLAGS = -lcurl
EXEC ?= torcomm
TORCOMM ?= torcomm.cpp
GENKEY = keys.cpp
GENKEY_EXEC = genkeys
HEADERS = settings.h keys.h

${EXEC}: ${TORCOMM} ${HEADERS}
	${CXX} ${CXXFLAGS} ${TORCOMM} -o ${EXEC} ${JSON_FLAGS}

${GENKEY_EXEC}: ${GENKEY} ${HEADERS}
	${CXX} ${CXXFLAGS} ${GENKEY} ${JSON_FLAGS} -o ${GENKEY_EXEC} ${CRYPTOPP_FLAGS} ${JSON_FLAGS} ${CURL_FLAGS}

all: ${TORCOMM} ${HEADERS}
	${CXX} ${CXXFLAGS} ${TORCOMM} -o ${EXEC} ${JSON_FLAGS}
	${CXX} ${CXXFLAGS} ${GENKEY} -o ${GENKEY_EXEC} ${CRYPTOPP_FLAGS} ${JSON_FLAGS} ${CURL_FLAGS}

clean:
	rm -rf ${OBJS}

