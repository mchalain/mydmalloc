
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#ifdef _PTHREAD
#include <pthread.h>
#endif
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

static void *_caller;
#define CALLER_LEVEL 0
#define CALLER _caller
#define RETURN_CALLER(val) void *val = _caller = __builtin_extract_return_addr(__builtin_return_address(CALLER_LEVEL))

#ifndef LOCAL
static void * (*pmalloc)(size_t) = NULL;
static void * (*pcalloc)(size_t, size_t) = NULL;
static void * (*prealloc)(void *, size_t) = NULL;
static void (*pfree)(void *) = NULL;
#endif

static void _lib_init() __attribute__((constructor));
static int _lib_inited = 0;
static void _lib_exit() __attribute__((destructor));

static FILE *output;

#ifdef _PTHREAD
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

static char print_all_info = 0;
static char iswarning()
{
    return print_all_info;
}

typedef struct leaks_info
{
  void * ptr;
  size_t size;
  void * caller;
#ifdef _PTHREAD
  pthread_t thread;
#else
  long thread;
#endif
  struct leaks_info *next;
} leaks_info_t;

leaks_info_t leaksinfo = {0};

#define FOOTER_PATTERN 0xAA
typedef struct leaks_footer
{
    unsigned char pattern[32];
} leaks_footer_t;

static char checkfooter(leaks_info_t *info)
{
    char ret = 1;
    int i;
    leaks_footer_t *footer = info->ptr + info->size;

    if (footer != NULL)
    {
        for (i = 0; i < sizeof(footer->pattern); i++)
        {
            if (footer->pattern[i] != FOOTER_PATTERN)
                ret = 0;
        }
    }
    else
        ret = 1;

    if (!ret)
    {
        fprintf(output, "memory overflow on pointer %p, size %lu allowed by %p\n", info->ptr, info->size, info->caller);
        fprintf(output, "pattern expected 0x%x obtained 0x", FOOTER_PATTERN);
        for (i = 0; i < sizeof(footer->pattern); i++)
        {
            printf("%02X", footer->pattern[i]);
        }
        printf("\n");
    }
    return ret;
}

char checkfooter_all = 0;

static void *pushleak(size_t size, void *caller)
{
	int pid;
	leaks_info_t *info = &leaksinfo;
    leaks_footer_t *footer;
#ifdef _PTHREAD
	pthread_t thread = pthread_self();
#else
	int thread = 0;
#endif

	if(!pmalloc)
	{
		pmalloc = (void * (*)(size_t))dlsym(RTLD_NEXT, "malloc");
	}

	while (info->next != NULL)
    {
        info = info->next;
        if (checkfooter_all)
            checkfooter(info);
    }
	info->next = pmalloc(sizeof(leaks_info_t) + size + sizeof(leaks_footer_t));
	info = info->next;
    memset(info, 0, sizeof(leaks_info_t) + size + sizeof(leaks_footer_t));
	info->ptr = info + sizeof(leaks_info_t);
	info->size = size;
    memset(info->ptr, 0, info->size);
    footer = info->ptr + info->size;

	info->next = NULL;
	info->caller = caller;
	info->thread = thread;
    {
        int i;
        for (i = 0; i < sizeof(footer->pattern); i++)
            footer->pattern[i] = FOOTER_PATTERN;
    }
    if (iswarning())
    {
        pid = (int)getpid();
        fprintf(output, "pushleak %p (size=%lu pid=%d thread=%lu fct(%p))\n", info->ptr, info->size, pid, info->thread, CALLER);
    }
    return info->ptr;
}

static void popleak(void * ptr, void *caller)
{
	int pid;
	leaks_info_t *info = &leaksinfo;
	leaks_info_t *pop;
#ifdef _PTHREAD
	pthread_t thread = pthread_self();
#else
	int thread = 0;
#endif

	if(!pfree)
	{
		pfree = (void (*)(void *))dlsym(RTLD_NEXT, "free");
	}

	while (info->next && info->next->ptr != ptr && info->next->thread != thread)
    {
        info = info->next;
        if (checkfooter_all)
            checkfooter(info);
    }
	if (info->next)
	{
		pop = info->next;
		info->next = pop->next;
        if (iswarning())
        {
            pid = (int)getpid();
            fprintf(output, "popleak %p (size=%lu pid=%d thread=%lu fct(%p))\n", pop->ptr, pop->size, pid, thread, caller);
        }
        checkfooter(pop);
		pfree(pop);
	}
	else if (iswarning())
		fprintf(output, "popleak unknown memory %p\n", ptr);
}

static void printleak()
{
	leaks_info_t *info = &leaksinfo;
	while (info->next != NULL)
	{
		info = info->next;
		printf("leak of %lu at %p allocated by %p thread %lu\n", info->size, info->ptr, info->caller, info->thread);
        checkfooter(info);
	}
}

static void sig_handler(int signal)
{
	if (signal == SIGUSR2)
	{
		lock();
		printleak();
		unlock();
	}
}

static void _lib_init()
{
	if (_lib_inited) return;
#ifdef _PTHREAD
	pthread_mutex_init(&mutex, NULL);
#endif
	lock();
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
	fprintf(output, "trace leak with signal %d\n",SIGUSR2);
	signal(SIGUSR2, sig_handler);
    {
        char *env = NULL;
        env = getenv("MALLOC_PRINT_ALL");
        if (env != NULL)
            print_all_info = atoi(env);
        env = getenv("MALLOC_OUTPUT");
        if (env != NULL)
        {
            output = fopen(env, "w+");
            if (output == NULL)
            {
                fprintf(stderr, "error %d \"%s\" during file(%s) opening\n", errno, strerror(errno), env);
                output = stderr;
            }
        }
        env = getenv("MALLOC_CHECKOVERFLOW");
        if (env != NULL)
            checkfooter_all = atoi(env);
    }
	_lib_inited = 1;
	unlock();
}

static void _lib_exit()
{
	leaks_info_t *info = &leaksinfo;
	leaks_info_t *previous;

	fprintf(output, "You close %s\n", __FILE__);

	lock();
	printleak();

	if(!pfree)
	{
		pfree = (void (*)(void *))dlsym(RTLD_NEXT, "free");
	}

	info = info->next;
	while(info && info->next)
	{
		previous = info;
		info = info->next;
		pfree(previous);
	}

	unlock();
}

void * malloc(size_t size)
{
	RETURN_CALLER(caller);
	void * ret = NULL;

	lock();
	ret = pushleak(size, caller);
	unlock();
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
	lock();
	if(pcalloc)
		ret = pcalloc(nelem, elsize);
	unlock();
	pushleak(ret, nelem * elsize, caller);
	return(ret);
}
*/
void * realloc(void *ptr, size_t size)
{
	RETURN_CALLER(caller);
	void * ret = NULL;

	lock();
	if (ptr)
		popleak(ptr, caller);

    ret = pushleak(size,caller);
	unlock();
	return(ret);

}

void free(void * ptr)
{
	RETURN_CALLER(caller);
	lock();
	if (ptr)
		popleak(ptr, caller);
	unlock();
}
