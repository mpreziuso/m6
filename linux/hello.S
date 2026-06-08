// hello.S — minimal aarch64 Linux ELF for m6-starnix bring-up.
//
// Calls only write(1, ...) and exit_group(0) — no libc, no musl init.
// Built with: aarch64-linux-musl-gcc -nostdlib -static -o hello hello.S

.section .text.start, "ax"
.global _start
_start:
    // write(1, msg, msg_end - msg)
    mov     x0, #1
    adr     x1, msg
    mov     x2, #(msg_end - msg)
    mov     x8, #64                 // __NR_write
    svc     #0

    // exit_group(0)
    mov     x0, #0
    mov     x8, #94                 // __NR_exit_group
    svc     #0

    // Should not reach here, but spin if exit_group returns.
1:  b       1b

.section .rodata
msg:
    .ascii  "hello, m6\n"
msg_end:
