ENTRY(_start)
SECTIONS {
    . = 0x40080000;
    .text   : { KEEP(*(.text._start .text._start.*)) *(.text .text.*) }
    .rodata : { *(.rodata .rodata.*) }
    .data   : { *(.data .data.*) }
    .bss    : { *(.bss .bss.*) *(COMMON) }
}
