TARGET = 80x
ENTRY = 0x900000000

.PHONY: all
all: ${TARGET}.elf

OPTS = -O -Wno-int-conversion -fno-strict-aliasing -masm=intel -nostartfiles
OPTS += -fwrapv -no-pie -Ttext=${ENTRY} -Tscript.ld -Wl,--build-id=none
OPTS += -fwrapv-pointer

${TARGET}.elf: ${TARGET}.c types.h
	gcc ${TARGET}.c -o ${TARGET}.elf ${OPTS}

.PHONY: clean
clean:
	-rm -f *.elf
