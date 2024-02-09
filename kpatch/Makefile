TARGET = 80x
ENTRY = 0x900000000

CC = gcc

.PHONY: all
all: $(TARGET).elf

CFLAGS = -O -Wno-int-conversion -fno-strict-aliasing -masm=intel -nostartfiles
CFLAGS += -fwrapv -no-pie -Ttext=$(ENTRY) -Tscript.ld -Wl,--build-id=none
CFLAGS += -fwrapv-pointer

$(TARGET).elf: $(TARGET).o
	$(CC) $(TARGET).o -o $(TARGET).elf $(CFLAGS)

.PHONY: clean
clean:
	-rm -f *.d *.o *.elf

%.d: %.c
	@set -e; \
	rm -f $@; \
	$(CC) -MM $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$;

src = $(TARGET).c

include $(src:.c=.d)
