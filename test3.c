#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void *function1(int id)
{
	char *buffer;

	printf("I am function %s (%p)\n", __FUNCTION__, function1);
	buffer = malloc(256);
	if (buffer)
	{
		strcpy(buffer, "Hello World");
		printf("%s %d at %p\n", buffer, id, buffer);
	}
	else
		printf("malloc error\n");
    return buffer;
}

int main(int argc, char **argv)
{
    void *ret[10];
    int i, j;
    int nbmalloc, nbfree;

    if (argc > 1)
    {
        nbmalloc = atoi(argv[1]);
        if (nbmalloc > 10)
            nbmalloc = 10;
    }
    if (argc > 2)
    {
        nbfree = atoi(argv[2]);
        if (nbfree > 10)
            nbfree = 10;
    }
    
    for (i = 0; i < nbmalloc; i++)
        ret[i] = function1(i);
    for (j = 0; j < nbfree;)
    {
        i = (random() * nbmalloc) / RAND_MAX;
        if (ret[i] != NULL)
        {
            printf("free %p\n", ret[i]);
            free(ret[i]);
            ret[i] = NULL;
            j++;
        }
    }
	return 0;
}
