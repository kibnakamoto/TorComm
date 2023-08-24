CXX = g++
CXX_FLAGS = -std=c++20
OPENSSL_FLAGS= -lssl -lcrypto
JSON_FLAGS= -ljsoncpp
EXEC ?= torcomm
TORCOMM ?= torcomm.cpp
GENKEY = keys.cpp
GENKEY_EXEC = genkeys
OBJS=n

${EXEC}: ${TORCOMM}
	${CXX} ${CXXFLAGS} ${TORCOMM} -o ${EXEC}

${GENKEY_EXEC}: ${GENKEY}
	${CXX} ${CXXFLAGS} ${GENKEY} -o ${GENKEY_EXEC} ${OPENSSL_FLAGS} ${JSON_FLAGS}

all: ${TORCOMM}
	${CXX} ${CXXFLAGS} ${TORCOMM} -o ${EXEC}
	${CXX} ${CXXFLAGS} ${GENKEY} -o ${GENKEY_EXEC} ${OPENSSL_FLAGS} ${JSON_FLAGS}
	cd pwnat && ${MAKE}
	

setup:
	cd pwnat && ${MAKE} && mv src/destination.o src/list.o src/message.o src/packet.o src/socket.o src/strlcpy.o src/strlcpy.o src/udpclient.o src/udpserver.o .

clean:
	rm -rf ${OBJS}
	cd pwnat && ${MAKE} clean

