// filename: vuln.c
#include <stdio.h>
#include <unistd.h>

char flag[]="/tmp/bof-rop-orw/flag";
char outbuf[40];

__attribute__((naked))
void syscall_gadget() {
    __asm__ volatile(
        "int $0x80;\n"
        "ret;\n"
    );
}

__attribute__((noinline, used))
void ROP_bank(void) {
    __asm__ volatile(
        "pop %eax; ret;\n"
        "pop %ebx; ret;\n"
        "pop %ecx; ret;\n"
        "pop %edx; ret;\n"
        "mov %eax, %ebx; ret;\n"
    );
}

void vuln() {
    char buf[64];
    puts("input:");
    read(0, buf, 400);
}

int main() {
    setregid(getegid(), getegid());
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}
