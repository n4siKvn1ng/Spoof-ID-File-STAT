ifndef TARGET_COMPILE
    $(error TARGET_COMPILE not set)
endif

ifndef KP_DIR
    KP_DIR = ../..
endif

CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld

# Add kernel source headers to include path
KERNEL_DIR ?= $(KP_DIR)/kernel
KERNEL_HEADERS = $(KERNEL_DIR)/include

INCLUDE_DIRS := . \
    include \
    patch/include \
    linux/include \
    linux/arch/arm64/include \
    linux/tools/arch/arm64/include \
    $(KERNEL_HEADERS)/uapi \
    $(KERNEL_HEADERS)/generated/uapi \
    $(KERNEL_HEADERS)/linux \
    $(KERNEL_HEADERS)/asm-generic \
    $(KERNEL_HEADERS)/asm-arm64

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := spoofSTAT.o

all: spoofSTAT.kpm

spoofSTAT.kpm: ${objs}
	${CC} -r -o $@ $^

%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -c -O2 -o $@ $<

.PHONY: clean
clean:
	rm -rf *.kpm
	find . -name "*.o" | xargs rm -f