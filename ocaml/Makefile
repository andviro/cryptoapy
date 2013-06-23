include ../Makefile.config

SOURCES = csp_stubs.cpp.c

MLSOURCES = 

OBJECTS = $(SOURCES:.c=.o)

MLOBJECTS = $(MLSOURCES:.ml=.cmx)

MLCFLAGS = $(foreach flg, $(CPPFLAGS), -ccopt $(flg))
MLCFLAGS += -ccopt -I../cpp/include 

MLLDFLAGS = $(foreach flg, $(LDFLAGS), -ccopt $(flg))
MLLDLIBS = $(foreach flg, $(LDLIBS), -cclib $(flg))

MLCLIBS = ../cpp/csp.a

TARGET = csp.cmxa

all: $(TARGET)
	ocamlopt $(TARGET) test.ml  $(MLLDLIBS) $(MLLDFLAGS) -o test

clean::
	rm -f $(MLOBJECTS) $(OBJECTS) $(TARGET)

$(TARGET): $(OBJECTS) $(MLOBJECTS)
	ocamlopt -a -o $@ $^ $(MLCLIBS) -cclib -lstdc++ $(MLLDLIBS) $(MLLDFLAGS) 

%.o: %.c
	ocamlopt -ccopt -xc++ $(MLCFLAGS) -c $<

%.cmx: %.ml
	ocamlopt -c -o $@ $<
