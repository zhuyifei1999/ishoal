OUTPUT := .

INCLUDES := -iquote $(abspath $(OUTPUT))
CFLAGS := -O2 -pipe -g -Wall
LDFLAGS := $(CFLAGS) -lbpf -lurcu-cds -lurcu -lpthread

# Define this to build on a system without multilib
# CLANGFLAGS := -D__x86_64__

PYTHON ?= python3.8
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
OBJ := $(SRC:%.c=$(OUTPUT)/%.o)

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(OUTPUT)/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
	PIPFLAGS += -qq
endif

all: $(OUTPUT)/ishoal

-include $(SRC:%.c=$(OUTPUT)/%.d)

$(OUTPUT)/xdpfilter.o: $(OUTPUT)/xdpfilter.skel.h
$(OUTPUT)/pkt.o: $(OUTPUT)/xdpfilter.skel.h

.PHONY: clean
.SECONDARY:
.DELETE_ON_ERROR:

clean:
	$(call msg,CLEAN,$(OUTPUT))
	$(Q)test -d $(OUTPUT) && find $(OUTPUT) \( -name '*.o' -o -name '*.d' -o -name '*.skel.h' \) -delete || true
	$(Q)test -d $(OUTPUT) && cd $(OUTPUT) && rm -f ishoal_native ishoal_py ishoal || true
	$(Q)test -d $(OUTPUT) && rm -rf $(OUTPUT)/py_dist_build || true
	$(Q)test -d $(OUTPUT) && find $(OUTPUT) -type d -empty -delete || true

$(OUTPUT):
	$(Q)mkdir -p $@

$(OUTPUT)/%.bpf.o: %.bpf.c | $(OUTPUT)
	$(call msg,CLNG-BPF,$@)
	$(Q)$(CLANG) -c $< -o $@ -MD -MP $(CFLAGS) $(INCLUDES) $(CLANGFLAGS) -target bpf
	$(Q)$(LLVM_STRIP) -g $@

$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(OUTPUT)/python.o: python.c | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) -c $< -o $@ -MD -MP $(PYTHON_CFLAGS) $(CFLAGS) $(INCLUDES)

$(OUTPUT)/tui.o: tui.c | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) -c $< -o $@ -MD -MP $(DIALOG_CFLAGS) $(CFLAGS) $(INCLUDES)

$(OUTPUT)/%.o: %.c | $(OUTPUT)
	$(Q)mkdir -p $(@D)
	$(call msg,CC,$@)
	$(Q)$(CC) -c $< -o $@ -MD -MP $(CFLAGS) $(INCLUDES)

$(OUTPUT)/ishoal_native: $(OBJ) | $(OUTPUT)
	$(call msg,LD,$@)
	$(Q)$(CC) $^ -o $@ $(PYTHON_LDFLAGS) $(DIALOG_LDFLAGS) $(LDFLAGS)
ifeq ($(DO_STRIP),1)
	$(call msg,STRIP,$@)
	$(Q)$(STRIP) $@
endif

$(OUTPUT)/py_dist_build: py_dist py_dist/**/* py-requirements.txt | $(OUTPUT)
	$(call msg,BUILD,$@)
	$(Q)mkdir -p $(OUTPUT)/py_dist_build && \
	cp -a py_dist/* $(OUTPUT)/py_dist_build && \
	$(PYTHON) -m pip install --no-binary :all: --no-compile $(PIPFLAGS) -Ur py-requirements.txt --target $(OUTPUT)/py_dist_build && \
	find $(OUTPUT)/py_dist_build -name '*.egg-info' -prune -exec rm -r {} \; && \
	find $(OUTPUT)/py_dist_build -name 'tests' -prune -exec rm -r {} \; && \
	find $(OUTPUT)/py_dist_build/chardet -mindepth 1 ! -path $(OUTPUT)/py_dist_build/chardet/version.py -prune -exec rm -r {} \; && \
	mv $(OUTPUT)/py_dist_build/chardet/{version.py,__init__.py} && \
	$(PYTHON) py-trimmer.py $(OUTPUT)/py_dist_build && \
	rm -rf $(OUTPUT)/py_dist_build/*.dist-info || \
	(rm -rf $(OUTPUT)/py_dist_build; exit 1)

$(OUTPUT)/ishoal_py: $(OUTPUT)/py_dist_build | $(OUTPUT)
	$(call msg,ZIPAPP,$@)
	$(Q)$(PYTHON) -m zipapp --compress $(OUTPUT)/py_dist_build -o $@

$(OUTPUT)/ishoal: $(OUTPUT)/ishoal_native $(OUTPUT)/ishoal_py | $(OUTPUT)
	$(call msg,CAT,$@)
	$(Q)cat $^ > $@ && chmod a+x $@
