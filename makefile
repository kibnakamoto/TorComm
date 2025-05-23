CXX = g++
CXXFLAGS = -std=c++2b -Wall -pedantic -Wextra -O4 -fcoroutines
CRYPTOPP_FLAGS =   -Iinclude -Llib -lcryptopp -lpthread
JSON_FLAGS = -ljsoncpp
CURL_FLAGS = -lcurl
BOOST_FLAGS = -lboost_filesystem
FLAGS = ${BOOST_FLAGS} ${CRYPTOPP_FLAGS} ${JSON_FLAGS} ${CURL_FLAGS}
PDF_FILE = TorComm.tex
PDF_DOC_FILES = TorComm.log TorComm.out TorComm.aux
EXEC = torcomm
HEADERS = settings.h keys.h settings.h comm.h message.h
# CPPS = torcomm.cpp keys.cpp settings.cpp
OBJS = torcomm.o keys.o settings.o comm.o message.o

all: ${OBJS}
	${CXX} ${CXXFLAGS} ${OBJS} -o ${EXEC} ${FLAGS}
	
%.o: %.cpp %.h
	${CXX} ${CXXFLAGS} $< -c ${FLAGS}

test: ${OBJS}
	${MAKE} debug
	${MAKE} -C test

security: ${OBJS}
	${MAKE}
	${MAKE} -C security

pdf:
	pdflatex TorComm.tex
	pdflatex TorComm.tex
	evince TorComm.pdf

pdf_clean:
	rm -rf ${PDF_DOC_FILES}

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
	rm -rf ${EXEC} ${OBJS} ${PDF_DOC_FILES}
	${MAKE} -C test clean

# don't clean security with 'make clean' as that can contain the executable for securing the key with password.
