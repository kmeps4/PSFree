SECTIONS
{
  .text : { *(.text.start) *(.text) }
  .data : { *(.data) }
  .bss : { *(.bss) }
  /DISCARD/ : { *(.*) }
}
