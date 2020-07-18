# source: https://mjg59.dreamwidth.org/18773.html
ARCH		= $(shell uname -m | sed s,i[3456789]86,ia32,)
LIB_PATH	= /usr/lib64
EFI_INCLUDE	= /usr/include/efi
EFI_INCLUDES	= -I$(EFI_INCLUDE) -I$(EFI_INCLUDE)/$(ARCH) -I$(EFI_INCLUDE)/protocol

EFI_CRT_OBJS	= /usr/lib64/crt0-efi-$(ARCH).o
EFI_LDS		= /usr/lib64/elf_$(ARCH)_efi.lds
EFI_LIBS	= -lefi -lgnuefi

CFLAGS		= -nostdlib \
		  -fno-stack-protector \
		  -fno-strict-aliasing \
		  -fpic \
		  -fshort-wchar \
		  -mno-red-zone \
		  -fno-builtin \
		  -Wall \
		  $(EFI_INCLUDES)
ifeq ($(ARCH),x86_64)
	CFLAGS  += -DEFI_FUNCTION_WRAPPER
endif

LDFLAGS	= -nostdlib \
	  -znocombreloc \
	  -T \
	  $(EFI_LDS) \
	  -shared \
	  -no-undefined \
	  -Bsymbolic \
	  -L$(LIB_PATH) \
	  $(EFI_CRT_OBJS)

TARGET	= efi_fb_res.efi
SHARED	= $(patsubst %.efi, %.so, $(TARGET))

SRC = $(wildcard *.c)
OBJ = $(patsubst %.c, %.o, $(SRC))

all: $(TARGET)

.PHONY: clean

clean:
	rm -f $(TARGET) *.so *.o

$(SHARED): $(OBJ)
	$(LD) -o $@ $(LDFLAGS) $^ $(EFI_LIBS)

%.efi: %.so
	objcopy -j .text \
		-j .sdata \
		-j .data \
		-j .dynamic \
		-j .dynsym \
		-j .rel*\
		-j .eh_frame \
		--target=efi-app-$(ARCH) $^ $@
