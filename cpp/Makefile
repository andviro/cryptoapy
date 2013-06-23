ARCH = ia32
#ARCH = 'amd64'

ifeq "$(ARCH)" "ia32"
	SIZE_VOID = 4
else
	SIZE_VOID = 8
endif

SOURCES = $(wildcard src/*.cpp)

OBJECTS = $(SOURCES:.cpp=.o)

CPPFLAGS += -Iinclude

ifndef COMSPEC
CPPFLAGS += -I/opt/cprocsp/include
CPPFLAGS += -I/opt/cprocsp/include/cpcsp
CPPFLAGS += -I/opt/cprocsp/include/asn1c/rtsrc
CPPFLAGS += -I/opt/cprocsp/include/asn1data
CPPFLAGS += -DUNIX
CPPFLAGS += -DHAVE_LIMITS_H
CPPFLAGS += -DHAVE_STDINT_H
CPPFLAGS += -DSIZEOF_VOID_P=$(SIZE_VOID)
CPPFLAGS += -DCP_IOVEC_USE_SYSTEM
endif

TARGET = csp.a

all: $(TARGET)

clean::
	rm -f $(OBJECTS) $(TARGET)

$(TARGET): $(OBJECTS)
	$(AR) r $@ $^
