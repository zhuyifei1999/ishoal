CFLAGS ?= -O2 -pipe -g
LDFLAGS ?= $(CFLAGS) -lbpf -lpthread -lminiupnpc

PYTHON ?= python3
PYTHON_CONFIG ?= $(PYTHON)-config
PYTHON_CFLAGS = $(shell $(PYTHON_CONFIG) --cflags) $(CFLAGS)
PYTHON_LDFLAGS = $(shell $(PYTHON_CONFIG) --ldflags) $(LDFLAGS)

LLC ?= llc
CLANG ?= clang

BPFTOOL ?= bpftool

sources = bpf_user.c ifinfo.c main.c netutil.c python.c remote.c thread.c util.c xsk.c

all: ishoal

include $(sources:.c=.d)

bpf_user.d: bpf_kern.skel.h

.PHONY: clean

clean:
	rm -f *.o *.d *.skel.h ishoal_native ishoal_py ishoal

%.d: %.c
	$(CC) -M $(shell $(PYTHON_CONFIG) --includes) $(CFLAGS) $< | \
		sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' > $@

%_kern.o: %_kern.c
	$(CLANG) -fno-common $(CFLAGS) -target bpf -emit-llvm -c $< -o - | \
		llc -march=bpf -mcpu=v2 -filetype=obj -o $@

%_kern.skel.h: %_kern.o
	$(BPFTOOL) gen skeleton $< > $@ || rm -f $@

python.o: python.c
	$(CC) $(PYTHON_CFLAGS) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

ishoal_native: $(sources:.c=.o)
	$(CC) $(PYTHON_LDFLAGS) $^ -o $@

ishoal_py: py_dist/**
	$(PYTHON) -m zipapp py_dist -o $@

ishoal: ishoal_native ishoal_py
	cat ishoal_native ishoal_py > ishoal
