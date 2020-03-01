CC=g++
CFLAGS=-c -Wall
LDFLAGS=
SOURCES= advancedEncrypt.cpp 
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=Assignment2.exe

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

%.o : %.cpp
	$(CC) $(CFLAGS) -c $<

clean:
	rm -rf *.o core
