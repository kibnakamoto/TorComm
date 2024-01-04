CXX = g++
CXXFLAGS = -std=c++23 -Wall -pedantic -Wextra -O4 -g
CRYPTOPP_FLAGS =   -Iinclude -Llib -lcryptopp -lpthread
JSON_FLAGS = -ljsoncpp
CURL_FLAGS = -lcurl
BOOST_FLAGS = -lboost_filesystem
FLAGS = ${BOOST_FLAGS} ${CRYPTOPP_FLAGS} ${JSON_FLAGS} ${CURL_FLAGS}
EXEC = file
OBJS = file.o ../../comm.o ../../message.o ../../keys.o ../../settings.o 

all: ${OBJS}
	${CXX} ${CXXFLAGS}  ${OBJS} -o ${EXEC} ${FLAGS}
	
%.o: %.cpp
	${CXX} ${CXXFLAGS} $< -c ${FLAGS}

.PHONY: clean
clean:
	rm -rf ${EXEC} *.o

