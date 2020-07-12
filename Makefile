CFLAGS ?= -O2 -g

LLC ?= llc
CLANG ?= clang

BPFTOOL ?= bpftool

sources = bpf_user.c ifinfo.c main.c netutil.c thread.c util.c xsk.c

all: ishoal

include $(sources:.c=.d)

bpf_user.d: bpf_kern.skel.h

.PHONY: clean

clean:
	rm -f *.o *.d *.skel.h ishoal

%.d: %.c
	$(CC) -M $(CFLAGS) $< | sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' > $@

%_kern.o: %_kern.c $(HEADERS)
	$(CLANG) -fno-common $(CFLAGS) -target bpf -emit-llvm -c $< -o - | \
		llc -march=bpf -mcpu=v2 -filetype=obj -o $@

%_kern.skel.h: %_kern.o
	$(BPFTOOL) gen skeleton $< > $@ || rm -f $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

ishoal: $(sources:.c=.o)
	$(CC) $(CFLAGS) -lbpf -lpthread $^ -o $@
