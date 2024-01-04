CXX = g++
CXXFLAGS = -std=c++23 -Wall -pedantic -Wextra -O4 -g
EXEC = test
OBJS = block/blocked.o crypto/crypto.o file/file.o misc/padding.o

all: ${OBJS}
	${MAKE} -C ../ debug
	${MAKE} -C block/
	${MAKE} -C crypto/
	${MAKE} -C file/
	${MAKE} -C misc/

.PHONY: clean
clean:
	rm -rf ${EXEC} ${OBJS}

