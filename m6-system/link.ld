/* Linker script for M6 userspace binaries */

/* Entry point */
ENTRY(_start)

/* User load address (above null guard) */
USER_BASE = 0x0000000000010000;

SECTIONS
{
    /* Start at user base address */
    . = USER_BASE;

    /* Code section */
    .text : ALIGN(4K)
    {
        /* Entry point first */
        *(.text.entry)
        *(.text .text.*)
    }

    /* Read-only data */
    .rodata : ALIGN(4K)
    {
        *(.rodata .rodata.*)
    }

    /* Initialised data */
    .data : ALIGN(4K)
    {
        *(.data .data.*)
    }

    /* Uninitialised data (BSS) */
    .bss : ALIGN(4K)
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    /* Program break (end of loaded segments) */
    . = ALIGN(4K);
    __brk = .;

    /* Discard unwanted sections */
    /DISCARD/ :
    {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
        *(.ARM.*)
    }
}
