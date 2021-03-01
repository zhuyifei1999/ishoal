CFLAGS ?= -O2 -pipe -g -Wall
LDFLAGS ?= $(CFLAGS) -lbpf -lurcu-cds -lurcu -lpthread

# Define this to build on a system without multilib
# CLANGFLAGS ?= -D__x86_64__

PYTHON ?= python3.8
PYTHON_CONFIG ?= $(PYTHON)-config
PYTHON_CFLAGS = $(shell $(PYTHON_CONFIG) --cflags)
PYTHON_LDFLAGS = $(shell $(PYTHON_CONFIG) --ldflags --embed)

DIALOG_CONFIG ?= dialog-config
DIALOG_CFLAGS = $(shell $(DIALOG_CONFIG) --cflags)
DIALOG_LDFLAGS = $(shell $(DIALOG_CONFIG) --libs)

LLC ?= llc
CLANG ?= clang

BPFTOOL ?= bpftool

SRC = $(filter-out ./c/bpf_kern.c, $(shell find . -type f -name '*.c'))
OBJ = $(patsubst %.c, %.o, $(SRC))

all: ishoal

include $(SRC:.c=.d)

c/bpf_user.d: c/bpf_kern.skel.h
c/pkt.d: c/bpf_kern.skel.h

.PHONY: clean

.DELETE_ON_ERROR:

clean:
	find . \( -name '*.o' -o -name '*.d' -o -name '*.skel.h' \) -delete
	rm -f ishoal_native ishoal_py ishoal
	rm -rf python_build

%.d: %.c
	$(CC) -M $< $(shell $(PYTHON_CONFIG) --includes) $(CFLAGS) | \
		sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' > $@

c/bpf_kern.d: c/bpf_kern.c c/pkt.impl.h
	$(CLANG) -M $< $(CFLAGS) $(CLANGFLAGS) -target bpf | \
		sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' > $@

c/bpf_kern.o: c/bpf_kern.c c/bpf_kern.d
	$(CLANG) -c $< -o - -fno-common $(CFLAGS) $(CLANGFLAGS) -target bpf -emit-llvm | \
		llc -o $@ -march=bpf -mcpu=v2 -filetype=obj

c/bpf_kern.skel.h: c/bpf_kern.o
	$(BPFTOOL) gen skeleton $< > $@

c/python.o: c/python.c
	$(CC) -c $< -o $@ $(PYTHON_CFLAGS) $(CFLAGS)

c/tui.o: c/tui.c
	$(CC) -c $< -o $@ $(DIALOG_CFLAGS) $(CFLAGS)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS)

ishoal_native: $(OBJ)
	$(CC) $^ -o $@ $(PYTHON_LDFLAGS) $(DIALOG_LDFLAGS) $(LDFLAGS)

python_build: python/**/* py-requirements.txt
	mkdir -p python_build && \
	cp -a python/* python_build && \
	$(PYTHON) -m pip install -Ur py-requirements.txt --target python_build && \
	find python_build -name '__pycache__' -prune -exec rm -r {} \; && \
	rm -rf python_build/*.dist-info || \
	(rm -rf python_build; exit 1)

ishoal_py: python_build
	$(PYTHON) -m zipapp --compress python_build -o $@

ishoal: ishoal_native ishoal_py
	cat $^ > $@ && chmod a+x $@
