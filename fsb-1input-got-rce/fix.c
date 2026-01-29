// filename: fix.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    char buf[200];

    setregid(getegid(), getegid());
    setvbuf(stdout, NULL, _IONBF, 0);

    puts("input:");
    fgets(buf, sizeof(buf), stdin);

    printf("%s\n", buf);
    puts(buf);

    return 0;
}
