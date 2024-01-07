CXX = g++
CXXFLAGS = -std=c++2b -Wall -pedantic -Wextra -O4 -g
CRYPTOPP_FLAGS =   -Iinclude -Llib -lcryptopp -lpthread
JSON_FLAGS = -ljsoncpp
CURL_FLAGS = -lcurl
BOOST_FLAGS = -lboost_filesystem
FLAGS = ${BOOST_FLAGS} ${CRYPTOPP_FLAGS} ${JSON_FLAGS} ${CURL_FLAGS}
EXEC = peer1
OBJS = ../../../comm.o ../../../message.o ../../../keys.o ../../../settings.o peer1.o 

all: ${OBJS}
	${CXX} ${CXXFLAGS}  ${OBJS} -o ${EXEC} ${FLAGS}
	rm -rf *.o
	
%.o: %.cpp
	${CXX} ${CXXFLAGS} $< -c ${FLAGS}

.PHONY: clean
clean:
	rm -rf ${EXEC} *.o

