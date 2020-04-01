CFLAGS ?= -Og -Wall -W -pedantic -g
CFLAGS += -std=c99 -DUTCP_DEBUG

BIN = selftest test

all: $(BIN)

utcp.o: utcp.c utcp.h utcp_priv.h

test: utcp.o test.c

stream: stream.c

selftest: utcp.o selftest.c

clean:
	rm -f *.o $(BIN)

astyle:
	@astyle --version | grep -q "Version 3" || (echo 'ERROR: astyle version 3 required!' 1>&2 && exit 1)
	astyle --options=.astylerc -nQ *.c *.h

.PHONY: clean astyle
