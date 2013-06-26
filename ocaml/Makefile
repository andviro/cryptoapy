include ../Makefile.config

SOURCES = csp_stubs.cpp.c
MLSOURCES = csp.ml

OBJECTS = $(SOURCES:.c=.o)
MLOBJECTS = $(MLSOURCES:.ml=.cmx)

CPPFLAGS += -I../cpp/include 
LDFLAGS := -L../cpp $(LDFLAGS)
LDLIBS := -lcsp $(LDLIBS)

MLCFLAGS = $(addprefix -ccopt ,$(CPPFLAGS))
MLLDFLAGS = $(addprefix -ccopt ,$(LDFLAGS))
MLLDLIBS = $(addprefix -cclib ,$(LDLIBS))


TARGET = ocamlcsp.cmxa

all: $(TARGET)
	ocamlopt -verbose -cc g++ $(TARGET) test.ml -o test$(EXE)

clean::
	rm -f $(MLOBJECTS) $(OBJECTS) $(TARGET) $(CLIBTARGET)

$(TARGET): $(MLOBJECTS) $(OBJECTS)
	ocamlopt -verbose -cc g++ -a -o $@ $(MLOBJECTS) $(OBJECTS) $(MLLDLIBS) $(MLLDFLAGS) 

$(CLIBTARGET): $(OBJECTS)
	$(AR) r $@ $^

%.o: %.c
	ocamlopt -verbose -cc g++ $(MLCFLAGS) -c $<

%.cmx: %.ml
	ocamlopt -verbose -cc g++ -c -o $@ $<
