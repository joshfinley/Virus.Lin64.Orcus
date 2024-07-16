ENTRY(_start)

SECTIONS
{
  . = 0x10000; /* Starting address for the output file */

  .text :
  {
    *(.text)
    *(.text.*)
    *(.rodata) /* Read-only data */
    *(.rodata.*)
  }

  /DISCARD/ : 
  { 
    *(.data)
    *(.data.*)
    *(.bss)
    *(.bss.*)
    *(.comment)
    *(.note.*)
    *(.eh_frame)
    *(.dynamic)
    *(.dynstr)
    *(.dynsym)
    *(.hash)
    *(.gnu.version)
    *(.gnu.version_d)
    *(.gnu.version_r)
    *(.got)
    *(.plt)
    *(.interp)
  }
}
