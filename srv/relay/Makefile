LLC ?= llc
CLANG ?= clang

STRIP ?= strip
LLVM_STRIP ?= llvm-strip

BPFTOOL ?= bpftool

CFLAGS := -O2 -pipe -g -Wall
LDFLAGS := $(CFLAGS) -lbpf

SRC := $(filter-out xdpfilter.bpf.c, $(wildcard *.c))
OBJ := $(SRC:%.c=%.o)

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst %,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
	PIPFLAGS += -qq
endif

all: ishoal-relay

-include $(SRC:%.c=%.d)

main.o: xdpfilter.skel.h

.PHONY: clean
.SECONDARY:
.DELETE_ON_ERROR:

clean:
	$(call msg,CLEAN)
	$(Q)rm -f *.o *.d *.skel.h ishoal-relay || true

$(O):
	$(Q)mkdir -p $@

%.bpf.o: %.bpf.c
	$(call msg,CLNG-BPF,$@)
	$(Q)$(CLANG) -c $< -o $@ -MD -MP $(CFLAGS) $(INCLUDES) $(CLANGFLAGS) -target bpf
	$(Q)$(LLVM_STRIP) -g $@

%.skel.h: %.bpf.o
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

%.o: %.c
	$(call msg,CC,$@)
	$(Q)$(CC) -c $< -o $@ -MD -MP $(CFLAGS) $(INCLUDES)

ishoal-relay: $(OBJ)
	$(call msg,LD,$@)
	$(Q)$(CC) $^ -o $@ $(PYTHON_LDFLAGS) $(DIALOG_LDFLAGS) $(LDFLAGS)
