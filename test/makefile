CXX = g++
CXXFLAGS = -std=c++23 -Wall -pedantic -Wextra -O4 -g
EXEC = block/block crypto/crypto file/file misc/pad
OBJS = block/*.o crypto/*.o file/*.o misc/*.o

all: ${OBJS}
	${MAKE} -C ../ debug
	${MAKE} -C block/
	${MAKE} -C crypto/
	${MAKE} -C file/
	${MAKE} -C misc/

.PHONY: clean
clean:
	rm -rf ${EXEC} ${OBJS}

