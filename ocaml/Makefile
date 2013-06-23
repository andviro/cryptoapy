ifndef COMSPEC
	EXE =
else
	EXE = .exe
endif

all: test$(EXE)
	./test$(EXE)

clean:
	rm -f *.cm[xo]
	rm -f test$(EXE)
	rm -f *_stubs.c

%.ml %_stubs.c: %.idl
	camlidl -no-include $<

%.cmx: %.ml
	ocamlopt -c $<

%.o: %.c
	ocamlopt -c $<


test$(EXE): wrap_stubs.c wrap.ml csp.cmx
	ocamlopt -o $@ $^


