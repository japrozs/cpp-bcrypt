CC = g++
CPPFLAGS = -Wall -Wextra -g -pedantic -I include --std=c++17
BIN = bin/main
SRC = $(wildcard src/*.cpp)
OBJS = $(SRC:.cpp=.o)

all: $(BIN) clean

$(BIN): $(OBJS)
	$(CC) -o $@ $^

src/%.o: %.cpp
	$(CC) $(CPPFLAGS) -c $<

clean:
	rm -rf src/*.o
	