CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra
LIBS = -lcrypto++
TARGET = hash_calculator
SOURCES = hash_calculator.cpp

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCES) $(LIBS)

clean:
	rm -f $(TARGET) *.o

.PHONY: clean