CFLAGS ?= -O2 -pipe -g -Wall
LDFLAGS ?= $(CFLAGS) -lbpf -lurcu -lpthread

# Define this to build on a x86_64 system without multilib
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

SRC = $(filter-out bpf_kern.c, $(wildcard *.c) $(wildcard extern/**/*.c))
OBJ = $(patsubst %.c, %.o, $(SRC))

all: ishoal

include $(SRC:.c=.d)

bpf_user.d: bpf_kern.skel.h

.PHONY: clean

.DELETE_ON_ERROR:

clean:
	rm -f *.o *.d *.skel.h ishoal_native ishoal_py ishoal
	rm -rf py_dist_build

%.d: %.c
	$(CC) -M $< $(shell $(PYTHON_CONFIG) --includes) $(CFLAGS) | \
		sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' > $@

%_kern.o: %_kern.c
	$(CLANG) -c $< -o - -fno-common $(CFLAGS) $(CLANGFLAGS) -target bpf -emit-llvm | \
		llc -o $@ -march=bpf -mcpu=v2 -filetype=obj

%_kern.skel.h: %_kern.o
	$(BPFTOOL) gen skeleton $< > $@

python.o: python.c
	$(CC) -c $< -o $@ $(PYTHON_CFLAGS) $(CFLAGS)

tui.o: tui.c
	$(CC) -c $< -o $@ $(DIALOG_CFLAGS) $(CFLAGS)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS)

ishoal_native: $(OBJ)
	$(CC) $^ -o $@ $(PYTHON_LDFLAGS) $(DIALOG_LDFLAGS) $(LDFLAGS)

py_dist_build: py_dist py_dist/** py-requirements.txt
	mkdir -p py_dist_build && \
	cp -a py_dist/* py_dist_build && \
	$(PYTHON) -m pip install -r py-requirements.txt --target py_dist_build && \
	rm -rf py_dist_build/*.dist-info || \
	(rm -rf py_dist_build; exit 1)

ishoal_py: py_dist_build
	$(PYTHON) -m zipapp py_dist_build -o $@

ishoal: ishoal_native ishoal_py
	cat $^ > $@ && chmod a+x $@
