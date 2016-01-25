#include <stdlib.h>
#include <pthread.h>

#define NTHREADS 3

void *thread_function1(void *dummy)
{
	char *buffer;

	printf("Thread number %lu\n", pthread_self());
	buffer = malloc(256);
	if (buffer)
	{
		strcpy(buffer, "Hello World\n");
		printf(buffer);
		//free(buffer);
	}
	else
		printf("malloc error\n");
	function();
}

void *thread_function2(void *dummy)
{
	char *buffer;

	printf("Thread number %lu\n", pthread_self());
	buffer = malloc(256);
	if (buffer)
	{
		strcpy(buffer, "Hello World\n");
		printf(buffer);
		free(buffer);
	}
	else
		printf("malloc error\n");
	function();
	while (1);
}

int function()
{
	printf("function\n");
}

int main(int argc, char **argv)
{
	pthread_t thread_id[NTHREADS];
	int i, j;

	for(i=0; i < NTHREADS - 1; i++)
	{
		pthread_create( &thread_id[i], NULL, thread_function1, NULL );
	}
	pthread_create( &thread_id[i], NULL, thread_function2, NULL );

	for(j=0; j < NTHREADS; j++)
	{
		pthread_join( thread_id[j], NULL); 
	}

	function();
	return 0;
}
