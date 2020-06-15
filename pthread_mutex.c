#include <pthread.h>

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t mutextid=0;
static int locknr=0;

void myd_mutex_init()
{
	pthread_mutex_init(&mutex, NULL);
}

void myd_lock()
{

#if 0
	if (pthread_mutex_trylock(&mutex))
	{
		if ( mutextid==pthread_self() )
		{
			++locknr;
			return;
		}
		else
		{
			pthread_mutex_lock(&mutex);
		}
	}
#else
	pthread_mutex_lock(&mutex);
#endif
	mutextid=pthread_self();
	locknr=1;
}

void myd_unlock()
{
#if 0
	--locknr;
	if (!locknr)
	{
		mutextid=0;
		pthread_mutex_unlock(&mutex);
	}
#else
	pthread_mutex_unlock(&mutex);
#endif
}

void myd_mutex_destroy()
{
}
