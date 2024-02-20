DEBUG ?= 0 


CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++23 -lsqlite3 -lssl -lcrypto
SRCDIR = src
BINDIR = bin
TARGET = $(BINDIR)/main

ifeq ($(DEBUG), 1)
CXXFLAGS += -g -O0
else
CXXFLAGS += -O3  
endif


SRCS = $(wildcard $(SRCDIR)/*.cpp)
OBJS = $(patsubst $(SRCDIR)/%.cpp, $(BINDIR)/%.o, $(SRCS))

all: build

run: build
	./bin/main


build: $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $^

$(BINDIR)/%.o: $(SRCDIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(BINDIR)/*.o $(TARGET)

.PHONY: build run clean 
