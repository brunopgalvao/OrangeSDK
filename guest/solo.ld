/* Solo guest layout (spec 01 §3.2, 03 §7.2).
 * Data lives below 4 GiB at the addresses the module will use. Code is given an
 * address only so the linker can resolve pc-relative references; the recompiler
 * never maps it into the instance's address space. */
ENTRY(solo_export_main)
SECTIONS
{
  . = 0x10000;
  .rodata : { *(.rodata .rodata.* .srodata .srodata.*) }

  . = ALIGN(0x1000) + 0x1000;
  __solo_rw_base = .;
  .data : { *(.data .data.* .sdata .sdata.*) }
  .bss (NOLOAD) : { *(.bss .bss.* .sbss .sbss.*) *(COMMON) }

  . = ALIGN(0x1000) + 0x1000;
  __solo_heap_base = .;

  /* Exports are reached only by the host, so keep them from garbage collection. */
  .text 0x40000000 : { KEEP(*(.text.solo_export_*)) *(.text .text.*) }

  /DISCARD/ : { *(.eh_frame .eh_frame_hdr .riscv.attributes .comment .note.*) }
}
