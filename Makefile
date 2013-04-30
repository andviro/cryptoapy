TARGET = csp
DLL = .so
PYTHON_INCS := $(shell python-config --includes)
PYTHON_LIBS := $(shell python-config --libs)
PYTHON_CFLAGS := $(shell python-config --cflags)

%$(DLL): %_wrap.c
	gcc -fPIC -shared -o _csp.so -I $(PYTHON_INCS) -L $(PYTHON_LIBS) \
		$(PYTHON_CFLAGS) $<

%_wrap.c: %.i
	swig -python $<

all: $(TARGET)$(DLL)
	nosetests
