/* Dynamically-linked smoke test for the m6-starnix loader.
 *
 * Unlike hellopie (static-PIE), this has a PT_INTERP of /lib/ld-musl-aarch64.so.1.
 * The kernel loader loads BOTH this binary and the interpreter, sets the entry
 * point to the interpreter and AT_BASE to its load address; the interpreter then
 * relocates everything, resolves `write`/`strlen` against itself (for musl the
 * dynamic linker is libc), and jumps to main.
 *
 * Requires /lib/ld-musl-aarch64.so.1 in the tmpfs — delivered via the initrd
 * `rootfs/` prefix (see the top-level Makefile). Run with `linux hellodyn`.
 */
#include <unistd.h>
#include <string.h>

int main(void) {
    const char *msg = "hello from dynamic musl\n";
    write(1, msg, strlen(msg));
    return 0;
}
