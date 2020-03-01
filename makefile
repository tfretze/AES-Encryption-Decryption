CC=g++
CFLAGS=-c -Wall
LDFLAGS=
SOURCES=MainAES.cpp  AdvancedEncrypt.h lookup.h 
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=Ass2AES.exe

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

%.o : %.cpp
	$(CC) $(CFLAGS) -c $<

clean:
	rm -rf *.o core
