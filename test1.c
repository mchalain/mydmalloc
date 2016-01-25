#include <stdlib.h>

int main(int argc, char **argv)
{
	char *buffer;

	printf("malloc(%p)\n", malloc);
	buffer = malloc(256);
	if (buffer)
	{
		strcpy(buffer, "Hello World\n");
		printf(buffer);
//		free(buffer);
	}
	else
		printf("malloc error\n");
	return 0;
}
