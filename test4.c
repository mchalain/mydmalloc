#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char *function1(int len)
{

    char *buffer = malloc(len);

    return buffer;
}

int main(int argc, char **argv)
{
    int len = 9;
    char *buffer = NULL;

    if (argc > 1)
        len = atoi(argv[1]);
    buffer =function1(10);
    memcpy(buffer, "12345678901234567890", len);
    buffer[len] = 0;
    printf("%s\n", buffer);
    free(buffer);
    return 0;
}
