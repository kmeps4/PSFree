SECTIONS
{
  .text : { *(.text.start) *(.text) }
  .rodata : { *(.rodata) }
  .data : { *(.data) }
  .bss : { *(.bss) }
  /DISCARD/ : { *(.comment* .note*) }
}
