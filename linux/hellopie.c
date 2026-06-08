/* Static-PIE smoke test for the m6-starnix loader.
 *
 * Built with -static-pie, this is an ET_DYN ELF with no PT_INTERP: the kernel
 * loader places it at an ASLR base and the libc startup self-relocates it
 * before main runs. It exercises the PIE / load-bias / AT_PHDR path that the
 * static, non-PIE busybox never touched.
 *
 * The `parts` table holds absolute pointers, so each entry needs an
 * R_AARCH64_RELATIVE relocation: if the loader applies the wrong load bias (or
 * AT_PHDR is wrong so libc can't find its own RELA section), these pointers come
 * out garbage and the program faults or prints junk — making this a real test of
 * relocation, not just of loading.
 *
 * Prefer building with musl (aarch64-linux-musl-gcc); glibc -static-pie also
 * works but pulls in a heavier startup.
 */
#include <unistd.h>
#include <stddef.h>

static const char p0[] = "hello ";
static const char p1[] = "from ";
static const char p2[] = "static-pie\n";

/* Array of absolute pointers -> one R_AARCH64_RELATIVE reloc per entry. */
static const char *const parts[] = { p0, p1, p2 };

static size_t slen(const char *s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

int main(void) {
    for (int i = 0; i < 3; i++) {
        const char *p = parts[i];
        write(1, p, slen(p));
    }
    return 0;
}
