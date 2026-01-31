// filename: vuln.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vuln() {
    char buf[64];

    puts("input1:");
    fgets(buf, sizeof(buf), stdin);
    printf(buf);
  
    puts("\ninput2:");
    gets(buf);
}

int main() {
    setregid(getegid(), getegid());
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    puts("done");
    return 0;
}
