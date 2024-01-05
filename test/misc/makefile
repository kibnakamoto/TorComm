CXX = g++
CXXFLAGS = -std=c++2b -Wall -pedantic -Wextra -O4 -g
EXEC = pad
OBJS = padding.o

all: ${OBJS}
	${CXX} ${CXXFLAGS} ${OBJS} -o ${EXEC} ${FLAGS}
	
%.o: %.cpp
	${CXX} ${CXXFLAGS} $< -c ${FLAGS}


.PHONY: clean
clean:
	rm -rf ${EXEC} ${OBJS}

