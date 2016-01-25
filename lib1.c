
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#ifdef _PTHREAD
#include <pthread.h>
#endif
#include <stdlib.h>

#define RETURN_CALLER(val) void *val = __builtin_extract_return_addr(__builtin_return_address(0))

#ifndef LOCAL
static void * (*pmalloc)(size_t) = NULL;
static void * (*pcalloc)(size_t, size_t) = NULL;
static void * (*prealloc)(void *, size_t) = NULL;
static void (*pfree)(void *) = NULL;
#endif

static int _lib_init() __attribute__((constructor));
static int _lib_inited = 0;
static void _lib_exit() __attribute__((destructor));

static FILE *output;

#ifdef _PTHREAD
static pthread_t main_thread=0;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t mutextid=0;
static int locknr=0;

static void lock()
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

static void unlock()
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
#else
static void lock()
{
}
static void unlock()
{
}
#endif

static int _lib_init()
{
	if (_lib_inited) return 0;
#ifdef _PTHREAD
	pthread_mutex_init(&mutex, NULL);
	lock();
	main_thread = pthread_self();
#else
	lock();
#endif
	output = stderr;
	fprintf(output, "You use %s\n", __FILE__);

	fprintf(output, "lib malloc(%p)\n", malloc);
#ifndef THREAD_SAFE
	if(!pmalloc)
	{
		pmalloc  = (void * (*)(size_t))dlsym(RTLD_NEXT, "malloc");
		fprintf(output, "dlsym malloc: %p\n", pmalloc);
	}
	else
		fprintf(output, "dlsym !!!!malloc: %p????????????\n", pmalloc);
	if(!pcalloc)
	{
		pcalloc =  (void * (*)(size_t, size_t))dlsym(RTLD_NEXT, "calloc");
		fprintf(output, "dlsym calloc: %p\n", pcalloc);
	}
	else
		fprintf(output, "dlsym !!!!calloc: %p????????????\n", pcalloc);
	if(!prealloc)
	{
		prealloc = (void * (*)(void *, size_t))dlsym(RTLD_NEXT, "realloc");
		fprintf(output, "dlsym realloc: %p\n", prealloc);
	}
	else
		fprintf(output, "dlsym !!!!realloc: %p????????????\n", prealloc);
	if(!pfree)
	{
		pfree = (void (*)(void *))dlsym(RTLD_NEXT, "free");
		fprintf(output, "dlsym free: %p\n", pfree);
	}
	else
		fprintf(output, "dlsym !!!!free: %p????????????\n", pfree);
#endif
	_lib_inited = 1;
	unlock();
	return 0;
}

static void _lib_exit()
{
	printf("coucou\n");
	lock();
	if ( main_thread != pthread_self())
		return;
	_lib_inited = 0;
	unlock();
}

void * malloc(size_t size)
{
	void * ret = NULL;

	RETURN_CALLER(caller);
#ifdef LOCAL
	void * (*pmalloc)(size_t) = NULL;
#endif
#ifdef THREAD_SAFE
	if (!pmalloc)
	{
		pmalloc = (void * (*)(size_t))dlsym(RTLD_NEXT, "malloc");
	}
#endif
	fprintf(output, "malloc(%p from %p) ", pmalloc, caller);
	lock();
	if(pmalloc)
		ret = pmalloc(size);
	unlock();
	fprintf(output, "%d at %p\n", size, ret);
	return(ret);
}

/* calloc is called by dlsym
void * calloc(size_t nelem, size_t elsize)
{
	void * ret = NULL;

	RETURN_CALLER(caller);
#ifdef LOCAL
	void * (*pcalloc)(size_t, size_t) = NULL;
#endif
#ifdef THREAD_SAFE
	if (!pcalloc)
	{
		fprintf(output, "dlsym calloc\n");
		pcalloc = (void * (*)(size_t, size_t))dlsym(RTLD_NEXT, "calloc");
	}
#endif
	fprintf(output, "calloc(%p from %p) ", pcalloc, caller);
	lock();
	if(pcalloc)
		ret = pcalloc(nelem, elsize);
	unlock();
	fprintf(output, "%d at %p\n", nelem * elsize, ret);
	return(ret);
}
*/
void * realloc(void *ptr, size_t size)
{
	void * ret = NULL;

	RETURN_CALLER(caller);
#ifdef LOCAL
	void * (*prealloc)(void *, size_t) = NULL;
#endif
#ifdef THREAD_SAFE
	if (!prealloc)
	{
		prealloc = (void * (*)(void *, size_t))dlsym(RTLD_NEXT, "realloc");
	}
#endif
	fprintf(output, "realloc(%p from %p) ", prealloc, caller);
	lock();
	if(prealloc)
		ret = prealloc(ptr, size);
	unlock();
	fprintf(output, "%d from %p to %p\n", size, ptr, ret);
	return(ret);

}

void free(void * ptr)
{
	RETURN_CALLER(caller);
#ifdef LOCAL
	void (*pfree)(void *) = NULL;
#endif
#ifdef THREAD_SAFE
	if (!pfree)
	{
		pfree = (void (*)(void *))dlsym(RTLD_NEXT, "free");
	}
#endif
	fprintf(output, "free(%p from %p) ", pfree, caller);
	lock();
	if(pfree)
		pfree(ptr);
	unlock();
	fprintf(output, "%p\n", ptr);
}
