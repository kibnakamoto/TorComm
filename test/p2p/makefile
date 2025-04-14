CXX = g++
CXXFLAGS = -std=c++2b -Wall -pedantic -Wextra -O4 -g -fcoroutines
CRYPTOPP_FLAGS =   -Iinclude -Llib -lcryptopp -lpthread
JSON_FLAGS = -ljsoncpp
CURL_FLAGS = -lcurl
BOOST_FLAGS = -lboost_filesystem
FLAGS = ${BOOST_FLAGS} ${CRYPTOPP_FLAGS} ${JSON_FLAGS} ${CURL_FLAGS}
EXEC = p2p
OBJS = ../../comm.o ../../message.o ../../keys.o ../../settings.o p2p.o 

all: ${OBJS}
	${CXX} ${CXXFLAGS} ${OBJS} -o ${EXEC} ${FLAGS}

# Dependencies on base
../../comm.o: ../../comm.cpp ../../comm.h
	${CXX} ${CXXFLAGS} -c ../../comm.cpp -o $@ ${FLAGS}

../../message.o: ../../message.cpp ../../message.h
	${CXX} ${CXXFLAGS} -c ../../message.cpp -o $@ ${FLAGS}

../../keys.o: ../../keys.cpp ../../keys.h
	${CXX} ${CXXFLAGS} -c ../../keys.cpp -o $@ ${FLAGS}

../../settings.o: ../../settings.cpp ../../settings.h
	${CXX} ${CXXFLAGS} -c ../../settings.cpp -o $@ ${FLAGS}

# Rule for p2p.o, which stays in test/p2p/
p2p.o: p2p.cpp ../../comm.h ../../message.h ../../keys.h ../../settings.h
	${CXX} ${CXXFLAGS} -c p2p.cpp -o p2p.o ${FLAGS}


# all: ${OBJS}
# 	${CXX} ${CXXFLAGS}  ${OBJS} -o ${EXEC} ${FLAGS}
# 	
# %.o: %.cpp ../../comm.cpp ../../message.cpp ../../keys.cpp ../../settings.cpp ../../comm.h ../../message.h ../../keys.h ../../settings.h
# 	${CXX} ${CXXFLAGS} $< -c ${FLAGS}

.PHONY: clean
clean:
	rm -rf ${EXEC} *.o

