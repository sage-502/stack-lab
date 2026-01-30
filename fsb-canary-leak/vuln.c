// filename: vuln.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vuln() {
    char buf[64];

    puts("input:");
    fgets(buf, sizeof(buf), stdin);

    printf(buf);   // Format String Vulnerability
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    puts("done");
    return 0;
}
