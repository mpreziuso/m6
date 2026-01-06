/* Kernel Linker Script */

/* Kernel is loaded at this virtual address */
KERNEL_VIRT_BASE = 0xFFFFFFFF80000000;

/* Physical load address (will be determined by bootloader) */
/* We use 0 as placeholder - actual address comes from BootInfo */

ENTRY(_start)

SECTIONS
{
    /* Start at kernel virtual base */
    . = KERNEL_VIRT_BASE;

    /* Text section (code) */
    .text : AT(ADDR(.text) - KERNEL_VIRT_BASE)
    {
        __text_start = .;
        KEEP(*(.text.entry))    /* Entry point first */
        *(.text .text.*)
        __text_end = .;
    }

    /* Exception vectors (must be 2KB aligned) */
    . = ALIGN(2048);
    .vectors : AT(ADDR(.vectors) - KERNEL_VIRT_BASE)
    {
        __vectors_start = .;
        KEEP(*(.vectors))
        __vectors_end = .;
    }

    /* Read-only data */
    . = ALIGN(4096);
    .rodata : AT(ADDR(.rodata) - KERNEL_VIRT_BASE)
    {
        __rodata_start = .;
        *(.rodata .rodata.*)
        __rodata_end = .;
    }

    /* Read-write data */
    . = ALIGN(4096);
    .data : AT(ADDR(.data) - KERNEL_VIRT_BASE)
    {
        __data_start = .;
        *(.data .data.*)
        __data_end = .;
    }

    /* BSS (uninitialised data) */
    . = ALIGN(4096);
    .bss : AT(ADDR(.bss) - KERNEL_VIRT_BASE)
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    /* Kernel stack */
    . = ALIGN(4096);
    .stack (NOLOAD) : AT(ADDR(.stack) - KERNEL_VIRT_BASE)
    {
        __stack_bottom = .;
        . += 64K;
        __stack_top = .;
    }

    /* End of kernel image */
    . = ALIGN(4096);
    __kernel_end = .;

    /* Calculate sizes */
    __kernel_size = __kernel_end - KERNEL_VIRT_BASE;

    /* Discard unwanted sections */
    /DISCARD/ :
    {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}
