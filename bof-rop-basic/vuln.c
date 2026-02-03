// filename: vuln.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

const char *binsh = "/bin/sh";

__attribute__((noinline, used))
void ROP_bank(void) {
    __asm__ volatile(
        "pop %eax; ret;\n"
        "pop %ebx; ret;\n"
        "pop %ecx; ret;\n"
        "pop %edx; ret;\n"
    );
}

__attribute__((noinline, used))
void syscall_stub(void) {
    __asm__ volatile("int $0x80; ret;");
}

__attribute__((noinline, used))
void do_setregid(void) {
    gid_t egid = getegid();
    setregid(egid, egid);
}

void vuln(void) {
    char buf[64];
    puts("input:");
    gets(buf);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    puts("done");
    return 0;
}
