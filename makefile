CXX = g++
CXXFLAGS = -std=c++23 -Wall -pedantic -Wextra -O4
CRYPTOPP_FLAGS =   -Iinclude -Llib -lcryptopp -lpthread
JSON_FLAGS = -ljsoncpp
CURL_FLAGS = -lcurl
BOOST_FLAGS = -lboost_filesystem
FLAGS = ${BOOST_FLAGS} ${CRYPTOPP_FLAGS} ${JSON_FLAGS} ${CURL_FLAGS}
EXEC = torcomm
HEADERS = settings.h keys.h settings.h comm.h message.h
# CPPS = torcomm.cpp keys.cpp settings.cpp
OBJS = torcomm.o keys.o settings.o comm.o message.o 

all: ${OBJS}
	${CXX} ${CXXFLAGS} ${OBJS} -o ${EXEC} ${FLAGS}
	
%.o: %.cpp ${HEADERS}
	${CXX} ${CXXFLAGS} $< -c ${FLAGS}

#${EXEC}: ${CPPS} ${HEADERS} ${OBJS}
#	${MAKE} all
#
#all: ${CPPS} ${HEADERS} ${OBJS}
#	${CXX} ${CXXFLAGS} settings.cpp -c ${CRYPTOPP_FLAGS} ${JSON_FLAGS} ${CURL_FLAGS}
#	${CXX} ${CXXFLAGS} keys.cpp     -c ${CRYPTOPP_FLAGS} ${JSON_FLAGS} ${CURL_FLAGS}
#	${CXX} ${CXXFLAGS} torcomm.cpp  -c ${JSON_FLAGS} ${BOOST_FLAGS}
#	${CXX} ${CXXFLAGS} ${OBJS} -o ${EXEC} ${FLAGS}

# debug mode
debug: ${OBJS}
	${CXX} ${CXXFLAGS} -g ${OBJS} -o ${EXEC} ${FLAGS}

.PHONY: clean
clean:
	rm -rf ${EXEC} ${OBJS}
