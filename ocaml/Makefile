include ../Makefile.config

SOURCES = csp_stubs.cpp.c
MLSOURCES = 

OBJECTS = $(SOURCES:.c=.o)
MLOBJECTS = $(MLSOURCES:.ml=.cmx)

MLCFLAGS = $(foreach flg, $(CPPFLAGS), -ccopt $(flg))
MLCFLAGS += -ccopt -I../cpp/include 

MLLDFLAGS = $(foreach flg, $(LDFLAGS), -ccopt $(flg))
MLLDLIBS = $(foreach flg, $(LDLIBS), -cclib $(flg))

MLLDFLAGS += -ccopt -L../cpp
MLLDLIBS += -cclib -lcsp

TARGET = ocamlcsp.cmxa

all: $(TARGET)
	ocamlopt $(TARGET) test.ml -o test$(EXE)

clean::
	rm -f $(MLOBJECTS) $(OBJECTS) $(TARGET) $(CLIBTARGET)

$(TARGET): $(MLOBJECTS) $(OBJECTS)
	ocamlopt -a -o $@ $(MLOBJECTS) $(MLLDLIBS) $(MLLDFLAGS) 
	$(AR) r $(@:.cmxa=.a) $(OBJECTS)

$(CLIBTARGET): $(OBJECTS)
	$(AR) r $@ $^

%.o: %.c
	ocamlopt -ccopt -xc++ $(MLCFLAGS) -c $<

%.cmx: %.ml
	ocamlopt -c -o $@ $<
