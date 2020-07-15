CFLAGS ?= -O2 -pipe -g
LDFLAGS ?= $(CFLAGS) -lbpf -lpthread -lminiupnpc

PYTHON ?= python3
PYTHON_CONFIG ?= $(PYTHON)-config
PYTHON_CFLAGS = $(shell $(PYTHON_CONFIG) --cflags)
PYTHON_LDFLAGS = $(shell $(PYTHON_CONFIG) --ldflags)

DIALOG_CONFIG ?= dialog-config
DIALOG_CFLAGS = $(shell $(DIALOG_CONFIG) --cflags)
DIALOG_LDFLAGS = $(shell $(DIALOG_CONFIG) --ldflags)

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
	rm -rf py_dist_build

%.d: %.c
	$(CC) -M $(shell $(PYTHON_CONFIG) --includes) $(CFLAGS) $< | \
		sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' > $@

%_kern.o: %_kern.c
	$(CLANG) -fno-common $(CFLAGS) -target bpf -emit-llvm -c $< -o - | \
		llc -march=bpf -mcpu=v2 -filetype=obj -o $@

%_kern.skel.h: %_kern.o
	$(BPFTOOL) gen skeleton $< > $@ || rm -f $@

python.o: python.c
	$(CC) $(PYTHON_CFLAGS) $(CFLAGS) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

ishoal_native: $(sources:.c=.o)
	$(CC) $(PYTHON_LDFLAGS) $(LDFLAGS) $^ -o $@

py_dist_build: py_dist py_dist/** py-requirements.txt
	mkdir -p py_dist_build && \
	cp -a py_dist/* py_dist_build && \
	$(PYTHON) -m pip install -r py-requirements.txt --target py_dist_build && \
	rm -rf py_dist_build/*.dist-info || \
	rm -rf py_dist_build

ishoal_py: py_dist_build
	$(PYTHON) -m zipapp py_dist_build -o $@

ishoal: ishoal_native ishoal_py
	cat $^ > $@ && chmod a+x $@ || rm -f $@
