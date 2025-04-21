CXX = g++
CXXFLAGS = -std=c++2b -Wall -pedantic -Wextra -O4 -g
CRYPTOPP_FLAGS =   -Iinclude -Llib -lcryptopp -lpthread
JSON_FLAGS = -ljsoncpp
CURL_FLAGS = -lcurl
BOOST_FLAGS = -lboost_filesystem
FLAGS = ${BOOST_FLAGS} ${CRYPTOPP_FLAGS} ${JSON_FLAGS} ${CURL_FLAGS}
EXEC = crypto
OBJS = crypto.o ../../comm.o ../../message.o ../../keys.o ../../settings.o 

all: ${OBJS}
	${CXX} ${CXXFLAGS} ${OBJS} -o ${EXEC} ${FLAGS}

# dependencies on base
../../comm.o: ../../comm.cpp ../../comm.h
	${CXX} ${CXXFLAGS} -c ../../comm.cpp -o $@ ${FLAGS}

../../message.o: ../../message.cpp ../../message.h
	${CXX} ${CXXFLAGS} -c ../../message.cpp -o $@ ${FLAGS}

../../keys.o: ../../keys.cpp ../../keys.h
	${CXX} ${CXXFLAGS} -c ../../keys.cpp -o $@ ${FLAGS}

../../settings.o: ../../settings.cpp ../../settings.h
	${CXX} ${CXXFLAGS} -c ../../settings.cpp -o $@ ${FLAGS}

crypto.o: crypto.cpp ../../comm.h ../../message.h ../../keys.h ../../settings.h
	${CXX} ${CXXFLAGS} -c crypto.cpp -o crypto.o ${FLAGS}

.PHONY: clean
clean:
	rm -rf ${EXEC} crypto.o

