// filename: vuln.c
#include <stdio.h>
#include <unistd.h>

char stage[0x1000];

__attribute__((naked))
void syscall_gadget() {
    __asm__ __volatile__(
        "int $0x80;\n"
        "ret;\n"
    );
}

__attribute__((used))
void trash1(int a, int b, int c) {
    volatile int x = a + b + c;
    (void)x;
}

__attribute__((used))
void trash2(int a, int b, int c) {
    volatile int x = b;
    volatile int y = a;
    (void)x; (void)y; (void)c;
}

__attribute__((used))
void trash3(int a, int b, int c) {
    volatile int x = 0;
    if (a == 0xdeadbeef) x = b;
    (void)x; (void)c;
}

void vuln() {
    char buf[64];
    puts("stage1:");
    read(0, buf, 400);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setregid(getegid(), getegid());
    vuln();
    return 0;
}
