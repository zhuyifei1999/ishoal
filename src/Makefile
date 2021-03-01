CFLAGS ?= -O2 -pipe -g -Wall
LDFLAGS ?= $(CFLAGS) -lbpf -lurcu-cds -lurcu -lpthread

# Define this to build on a system without multilib
# CLANGFLAGS ?= -D__x86_64__

PYTHON ?= python3.8
PYTHON_CONFIG ?= $(PYTHON)-config
PYTHON_CFLAGS = $(shell $(PYTHON_CONFIG) --cflags)
PYTHON_LDFLAGS = $(shell $(PYTHON_CONFIG) --ldflags --embed)

PIPFLAGS ?=

DIALOG_CONFIG ?= dialog-config
DIALOG_CFLAGS = $(shell $(DIALOG_CONFIG) --cflags)
DIALOG_LDFLAGS = $(shell $(DIALOG_CONFIG) --libs)

LLC ?= llc
CLANG ?= clang

LLVM_STRIP ?= llvm-strip

BPFTOOL ?= bpftool

SRC = $(filter-out xdpfilter.bpf.c, $(wildcard *.c) $(wildcard extern/**/*.c))
OBJ = $(patsubst %.c, %.o, $(SRC))

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
	PIPFLAGS += -qq
endif

all: ishoal

include $(SRC:.c=.d)

xdpfilter.d: xdpfilter.skel.h
pkt.d: xdpfilter.skel.h
xdpfilter.bpf.d: pkt.impl.h

.PHONY: clean
.SECONDARY:
.DELETE_ON_ERROR:

clean:
	$(call msg,CLEAN)
	$(Q)rm -f *.o *.d *.skel.h ishoal_native ishoal_py ishoal
	$(Q)rm -rf py_dist_build

%.d: %.c
	$(Q)$(CC) -M $< $(shell $(PYTHON_CONFIG) --includes) $(CFLAGS) | \
		sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' > $@

%.bpf.d: %.bpf.c
	$(Q)$(CLANG) -M $< $(CFLAGS) $(CLANGFLAGS) -target bpf | \
		sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' > $@

%.bpf.o: %.bpf.c %.bpf.d
	$(call msg,CLNG-BPF,$@)
	$(Q)$(CLANG) -c $< -o - -fno-common $(CFLAGS) $(CLANGFLAGS) -target bpf -emit-llvm | \
		llc -o $@ -march=bpf -mcpu=v2 -filetype=obj
	$(Q)$(LLVM_STRIP) -g $@

%.skel.h: %.bpf.o
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

python.o: python.c
	$(call msg,CC,$@)
	$(Q)$(CC) -c $< -o $@ $(PYTHON_CFLAGS) $(CFLAGS)

tui.o: tui.c
	$(call msg,CC,$@)
	$(Q)$(CC) -c $< -o $@ $(DIALOG_CFLAGS) $(CFLAGS)

%.o: %.c
	$(call msg,CC,$@)
	$(Q)$(CC) -c $< -o $@ $(CFLAGS)

ishoal_native: $(OBJ)
	$(call msg,LD,$@)
	$(Q)$(CC) $^ -o $@ $(PYTHON_LDFLAGS) $(DIALOG_LDFLAGS) $(LDFLAGS)

py_dist_build: py_dist py_dist/**/* py-requirements.txt
	$(call msg,PIP,$@)
	$(Q)mkdir -p py_dist_build && \
	cp -a py_dist/* py_dist_build && \
	$(PYTHON) -m pip install $(PIPFLAGS) -Ur py-requirements.txt --target py_dist_build && \
	find py_dist_build -name '__pycache__' -prune -exec rm -r {} \; && \
	rm -rf py_dist_build/*.dist-info || \
	(rm -rf py_dist_build; exit 1)

ishoal_py: py_dist_build
	$(call msg,ZIPAPP,$@)
	$(Q)$(PYTHON) -m zipapp --compress py_dist_build -o $@

ishoal: ishoal_native ishoal_py
	$(call msg,CAT,$@)
	$(Q)cat $^ > $@ && chmod a+x $@
