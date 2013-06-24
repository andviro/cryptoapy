include ../Makefile.config

SOURCES = $(wildcard src/*.cpp)

OBJECTS = $(SOURCES:.cpp=.o)

CPPFLAGS += -Iinclude

TARGET = libcsp.a

all: $(TARGET)

clean::
	rm -f $(OBJECTS) $(TARGET)

$(TARGET): $(OBJECTS)
	$(AR) r $@ $^
