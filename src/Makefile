O := .

INCLUDES := -iquote $(abspath $(O))
CFLAGS := -O2 -pipe -g -Wall
LDFLAGS := $(CFLAGS) -lbpf -lurcu-cds -lurcu -lpthread -lunwind

# Define this to build on a system without multilib
# CLANGFLAGS := -D__x86_64__

PYTHON ?= python3.9
PYTHON_CONFIG ?= $(PYTHON)-config
PYTHON_CFLAGS := $(shell $(PYTHON_CONFIG) --cflags)
PYTHON_LDFLAGS := $(shell $(PYTHON_CONFIG) --ldflags --embed)

PIPFLAGS :=

DIALOG_CONFIG ?= dialog-config
DIALOG_CFLAGS := $(shell $(DIALOG_CONFIG) --cflags)
DIALOG_LDFLAGS := $(shell $(DIALOG_CONFIG) --libs)

LLC ?= llc
CLANG ?= clang

STRIP ?= strip
LLVM_STRIP ?= llvm-strip

BPFTOOL ?= bpftool

SRC := $(filter-out xdpfilter.bpf.c, $(wildcard *.c) $(wildcard extern/**/*.c))
OBJ := $(SRC:%.c=$(O)/%.o)

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(O)/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
	PIPFLAGS += -qq
endif

all: $(O)/ishoal

-include $(SRC:%.c=$(O)/%.d)

$(O)/xdpfilter.o: $(O)/xdpfilter.skel.h
$(O)/pkt.o: $(O)/xdpfilter.skel.h

.PHONY: clean
.SECONDARY:
.DELETE_ON_ERROR:

clean:
	$(call msg,CLEAN,$(O))
	$(Q)test -d $(O) && find $(O) \( -name '*.o' -o -name '*.d' -o -name '*.skel.h' \) -delete || true
	$(Q)test -d $(O) && cd $(O) && rm -f ishoal_native ishoal_py ishoal || true
	$(Q)test -d $(O) && rm -rf $(O)/py_dist_build || true
	$(Q)test -d $(O) && find $(O) -type d -empty -delete || true

$(O):
	$(Q)mkdir -p $@

$(O)/%.bpf.o: %.bpf.c | $(O)
	$(call msg,CLNG-BPF,$@)
	$(Q)$(CLANG) -c $< -o $@ -MD -MP $(CFLAGS) $(INCLUDES) $(CLANGFLAGS) -target bpf
	$(Q)$(LLVM_STRIP) -g $@

$(O)/%.skel.h: $(O)/%.bpf.o | $(O)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(O)/python.o: python.c | $(O)
	$(call msg,CC,$@)
	$(Q)$(CC) -c $< -o $@ -MD -MP $(PYTHON_CFLAGS) $(CFLAGS) $(INCLUDES)

$(O)/tui.o: tui.c | $(O)
	$(call msg,CC,$@)
	$(Q)$(CC) -c $< -o $@ -MD -MP $(DIALOG_CFLAGS) $(CFLAGS) $(INCLUDES)

$(O)/%.o: %.c | $(O)
	$(Q)mkdir -p $(@D)
	$(call msg,CC,$@)
	$(Q)$(CC) -c $< -o $@ -MD -MP $(CFLAGS) $(INCLUDES)

$(O)/ishoal_native: $(OBJ) | $(O)
	$(call msg,LD,$@)
	$(Q)$(CC) $^ -o $@ $(PYTHON_LDFLAGS) $(DIALOG_LDFLAGS) $(LDFLAGS)
ifeq ($(DO_STRIP),1)
	$(call msg,STRIP,$@)
	$(Q)$(STRIP) -g $@
endif

$(O)/py_dist_build: py_dist py_dist/**/* py-requirements.txt | $(O)
	$(call msg,BUILD,$@)
	$(Q)mkdir -p $(O)/py_dist_build && \
	cp -a py_dist/* $(O)/py_dist_build && \
	$(PYTHON) -m pip install --no-binary :all: --no-compile $(PIPFLAGS) -Ur py-requirements.txt --target $(O)/py_dist_build && \
	find $(O)/py_dist_build -name '*.egg-info' -prune -exec rm -r {} \; && \
	find $(O)/py_dist_build -name 'tests' -prune -exec rm -r {} \; && \
	$(PYTHON) py-trimmer.py $(O)/py_dist_build && \
	rm -rf $(O)/py_dist_build/*.dist-info || \
	(rm -rf $(O)/py_dist_build; exit 1)

$(O)/ishoal_py: $(O)/py_dist_build | $(O)
	$(call msg,ZIPAPP,$@)
	$(Q)$(PYTHON) -m zipapp --compress $(O)/py_dist_build -o $@

$(O)/ishoal: $(O)/ishoal_native $(O)/ishoal_py | $(O)
	$(call msg,CAT,$@)
	$(Q)cat $^ > $@ && chmod a+x $@
