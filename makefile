CXX = g++
CXX_FLAGS = -g -std=c++20 -Wall -pedantic -Wextra -O4
CRYPTOPP_FLAGS =   -Iinclude -Llib -lcryptopp -lpthread
JSON_FLAGS = -ljsoncpp
EXEC ?= torcomm
TORCOMM ?= torcomm.cpp
GENKEY = keys.cpp
GENKEY_EXEC = genkeys
OBJS=n

${EXEC}: ${TORCOMM}
	${CXX} ${CXXFLAGS} ${TORCOMM} -o ${EXEC}

${GENKEY_EXEC}: ${GENKEY}
	${CXX} ${CXXFLAGS} ${GENKEY} -o ${GENKEY_EXEC} ${CRYPTOPP_FLAGS} ${JSON_FLAGS}

all: ${TORCOMM}
	${CXX} ${CXXFLAGS} ${TORCOMM} -o ${EXEC}
	${CXX} ${CXXFLAGS} ${GENKEY} -o ${GENKEY_EXEC} ${CRYPTOPP_FLAGS} ${JSON_FLAGS}
	cd pwnat && ${MAKE}
	

setup:
	cd pwnat && ${MAKE} # && mv src/destination.o src/list.o src/message.o src/packet.o src/socket.o src/strlcpy.o src/strlcpy.o src/udpclient.o src/udpserver.o .

clean:
	rm -rf ${OBJS}
	cd pwnat && ${MAKE} clean

