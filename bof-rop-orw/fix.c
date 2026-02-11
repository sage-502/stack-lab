// filename: fix.c
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
    ssize_t n = read(0, buf, sizeof(buf) - 1);
  
    if (n <= 0)
        return;

    buf[n] = '\0';
}

int main() {
    setregid(getegid(), getegid());
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}
