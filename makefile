CXX = g++
CXX_FLAGS = -std=c++20
EXEC ?= torcomm
TORCOMM ?= comm.cpp
OBJS ?= comm.o

${EXEC}: ${TORCOMM}
	${CXX} ${CXXFLAGS} ${TORCOMM} -o ${EXEC}

all: ${TORCOMM}
	${CXX} ${CXXFLAGS} ${TORCOMM} -o ${EXEC}
	cd pwnat && ${MAKE}
	rm -rf src/destination.o src/list.o src/message.o src/packet.o  src/socket.o src/strlcpy.o src/strlcpy.o src/udpclient.o src/udpserver.o
	cd ..

setup:
	cd pwnat && ${MAKE} && rm -rf src/client.o src/destination.o src/list.o src/message.o src/packet.o  src/socket.o src/strlcpy.o src/strlcpy.o src/udpclient.o src/udpserver.o

clean:
	rm -rf ${OBJS}
	cd pwnat && ${MAKE} clean

