include ../../Makefile.config

SOURCES = $(wildcard src/*.cpp)

OBJECTS = $(SOURCES:.cpp=.o)

CPPFLAGS += -Iinclude

ifdef DEBUG
	CPPFLAGS += -DDEBUG_LOG
endif

TARGET = libcsp.a

all: $(TARGET)

clean::
	rm -f $(OBJECTS) $(TARGET)

$(TARGET): $(OBJECTS)
	$(AR) r $@ $^
