#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    char buf[40];
    puts("Welcome to hxp's Echo Service!");
    while (1)
    {
        printf("> ");
        ssize_t len = read(0, buf, 0x60);
        if (len <= 0) return 0;
        if (buf[len - 1] == '\n') buf[--len] = 0;
        if (len == 0) return 0;
        puts(buf);
    }
}
const void* foo = system;
