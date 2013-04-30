TARGET = csp
DLL = .so
PYTHON_INCS := $(shell python-config --includes)
PYTHON_LIBS := $(shell python-config --libs)
PYTHON_CFLAGS := $(shell python-config --cflags)
LSB_LD = /lib/ld-lsb.so.3
CSP_DIR = /opt/cprocsp
CSP_INCLUDE = /opt/cprocsp/include
add_CPPFLAGS = -DHAVE_STDINT_H
SIZEOF_VOID_P = 4
CSP_LIB = /opt/cprocsp/lib/ia32
CSP_EXTRA_LIBS = -lpthread
CFLAGS = -DUNIX -DHAVE_LIMITS_H $(ARCH_FLAGS) $(PYTHON_CFLAGS) $(PYTHON_INCS) -I$(CSP_INCLUDE) -I$(CSP_INCLUDE)/cpcsp -I$(CSP_INCLUDE)/asn1c/rtsrc -I$(CSP_INCLUDE)/asn1data -DSIZEOF_VOID_P=$(SIZEOF_VOID_P) -g
LDFLAGS= $(ARCH_FLAGS) -L$(CSP_LIB) -lasn1data -lssp -lcapi10 -lcapi20 $(CSP_EXTRA_LIBS) $(PYTHON_LIBS) -g

%$(DLL): %_wrap.c
	gcc -fPIC -shared -o _csp.so $(CFLAGS) -L $(LDFLAGS) $<

%_wrap.c: %.i
	swig -python $<

all: $(TARGET)$(DLL)
	nosetests
