CXX = g++
CXX_FLAGS = -std=c++20
EXEC ?= torcomm
TORCOMM ?= comm.cpp
OBJS ?= comm.o

${EXEC}: ${TORCOMM}
	${CXX} ${CXXFLAGS} ${TORCOMM} -o ${EXEC}

all: ${TORCOMM}
	${CXX} ${CXXFLAGS} ${TORCOMM} -o ${EXEC}
	cd pwnat && ${MAKE} && cd ..

setup:
	cd pwnat && ${MAKE} && cd ..

clean:
	rm -rf ${OBJS}
	cd pwnat && ${MAKE} clean && cd ..

