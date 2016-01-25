/* Library interposer to collect malloc/calloc/realloc 
 * statistics
 * and produce a histogram of their use.
 * cc -o malloc_hist.so -G -Kpic malloc_hist.c
 * setenv LD_PRELOAD $cwd/malloc_hist.so
 * run the application
 * unsetenv LD_PRELOAD
 *
 * The results will be in 
 * /tmp/malloc_histogram.<prog_name>.<pid>
 * for each process invoked by current application.
 */
#define _GNU_SOURCE

#include <dlfcn.h>
#include <memory.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>

void *libc_handle;
static FILE* output;

void * callerptr = 0;
#if 0
#define STORE_CALLER_PTR(addr) \
  do {\
   asm(" .state32                  ;this is 32BIS code           ");\
   asm(" .newblock                                               ");\
   asm(" STMFD R13!,{R0}           ;save R0                      ");\
   asm(" LDR   R0,$1                                             ");\
   asm(" STR   LR,[R0]             ;save LR                      ");\
   asm(" LDMFD R13!,{R0   }        ;Restore R0                   ");\
   asm(" B $2                                                    ");\
   asm(" .global #addr                                           ");\
   asm(" .align                                                  ");\
   asm("$1: .long #addr                                          ");\
   asm("$2:                                                      ");\
  } while(0)
#else
#define STORE_CALLER_PTR(addr)
#endif

/*
__attribute__((constructor)) static void _mymalloc_init()
{
	fprintf(stderr, "Mymalloc initialization\n");
	output = stderr;
	libc_handle = dlopen("libc.so", RTLD_LAZY);
	if (!libc_handle)
	{
		fprintf(output, "%s\n", dlerror());
		exit(-1);
	}
}
*/

/*
__attribute__((destructor)) static void _mymalloc_exit()
{
	dlclose(libc_handle);
}
*/

#ifdef HISTORY
#include <procfs.h>

typedef struct data {
  int histogram[32];
  char * caller;
} data_t;

data_t mdata = { 
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0, 
  "malloc"};

data_t cdata = { 
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0, 
  "calloc"};

data_t rdata = { 
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0, 
  "realloc"};

data_t fdata = { 
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0, 
  "free"};

static int pid;
static char prog_name[32];
static char path[64];
static int print_data(data_t * ptr)

static void done()
{
  fprintf(output, "Mymalloc: prog_name=%s\n", prog_name);
  print_data(&mdata);
  print_data(&cdata);
  print_data(&rdata);
}

static int print_data(data_t * ptr)
{
  int i;

  fprintf(output, "******** %s **********\n", 
    ptr->caller);
  for(i=0;i<32;i++)
      if(i < 10 || ptr->histogram[i])
    fprintf(output, "%10u\t%10d\n", 1<<i, 
    ptr->histogram[i]);
}
#endif

#ifdef LEAKS
typedef struct leaks_info
{
  void * ptr;
  size_t size;
  void * func_caller;
  struct leaks_info *next;
} leaks_info_t;

leaks_info_t leaksinfo = { NULL, 0, NULL};

static void pushleak(void * ptr, size_t size)
{
  static void * (*func)();
  void * ret;
  int pid;
  leaks_info_t *info = &leaksinfo;

  pid = (int)getpid();
  fprintf(output, "Mymalloc: pushleak %p (size=%d pid=%d pusher (%p))\n", ptr, size, pid, callerptr);
  if(!func) {
    func = (void *(*)()) dlsym(RTLD_NEXT, "malloc");
  }

  while (info->next != NULL) info = info->next;
  info->next = func(sizeof(leaks_info_t));
  info = info->next;
  info->ptr = ptr;
  info->size = size;
  info->next = NULL;
  info->func_caller = callerptr;
}

static void popleak(void * ptr)
{
  static void * (*func)();
  void * ret;
  int pid;
  leaks_info_t *info = &leaksinfo;
  leaks_info_t *pop;

  if(!func) {
    func = (void *(*)()) dlsym(RTLD_NEXT, "free");
  }

  while (info->next->ptr != ptr) info = info->next;
  pop = info->next;
  info->next = pop->next;
  pid = (int)getpid();
  fprintf(output, "Mymalloc: popleak %p (size=%d pid=%d pusher(%p) poper(%p))\n", pop->ptr, pop->size, pid, pop->func_caller, callerptr);
  func(pop);
}
#endif

#ifdef HISTORY
void exit(int status)
{
  char procbuf[32];
  psinfo_t psbuf;
  int fd;

  /* Get current executable's name using proc(4) 
     interface */
  pid = (int)getpid();
  (void)sprintf(procbuf, "/proc/%ld/psinfo", (long)pid);
  if ((fd = open(procbuf, O_RDONLY)) != -1)
  {
    if (read(fd, &psbuf, sizeof(psbuf)) == sizeof(psbuf))
      sprintf(prog_name, "%s.%d", psbuf.pr_fname, pid);
    else
      sprintf(prog_name, "%s.%d", "unknown", pid);
  }
  else
    sprintf(prog_name, "%s.%d", "unknown", pid);
  sprintf(path, "%s%s", "/tmp/malloc_histogram.", 
  prog_name);

  /* Open the file here since
     the shell closes all file descriptors 
     before calling exit() */
  output = fopen(path, "w");
  if(output)
      done();
#ifdef LEAKS
#endif
  
  (*((void (*)())dlsym(libc_handle, "exit")))(status);
}
#endif

#ifdef HISTORY
static int bump_counter(data_t * ptr, int size)
{
  static mutex_t lock;
  int size_orig;
  int i = 0;

  size_orig = size;
  while(size /= 2)
      i++;
  if(1<<i < size_orig)
      i++;

  /* protect histogram data if application is 
     multithreaded */  
  mutex_lock(&lock);
  ptr->histogram[i]++;
  mutex_unlock(&lock);
}
#endif

void * malloc(size_t size)
{
  void * ret = NULL;
/*
  STORE_CALLER_PTR(callerptr);
  static void * (*func)(size_t);

  fprintf(output, "Mymalloc: malloc ");
  if(!func)
    *(void **) (&func) = dlsym(libc_handle, "malloc");


  ret = (*func)(size);
  int pid = (int)getpid();
  fprintf(output, "%p (size=%d pid=%d caller (%p))\n", ret, size, pid, callerptr);

#ifdef HISTORY
  bump_counter(&mdata, size);
#endif  
#ifdef LEAKS
  pushleak(ret, size);
#endif
*/
  return(ret);
}

void * calloc(size_t nelem, size_t elsize)
{
  void * ret = NULL;
/*
  STORE_CALLER_PTR(callerptr);
  static void * (*func)(size_t, size_t);
  int i;

  fprintf(output, "Mymalloc: calloc ");
  if(!func)
    *(void **) (&func) =  dlsym(libc_handle, "calloc");

  ret = (*func)(nelem, elsize);
  int pid = (int)getpid();
  fprintf(output, "%p (size=%d pid=%d caller (%p))\n", ret, nelem * elsize, pid, callerptr);

#ifdef HISTORY
  for(i=0;i<nelem;i++)
      bump_counter(&cdata, elsize);
#endif
#ifdef LEAKS
  pushleak(ret, nelem * elsize);
#endif
*/
  return(ret);
}

void * realloc(void *ptr, size_t size)
{
  void * ret = NULL;
/*
  STORE_CALLER_PTR(callerptr);
  static void * (*func)(void *, size_t);

  fprintf(output, "Mymalloc: realloc ");
  if(!func)
    *(void **) (&func) = dlsym(libc_handle, "realloc");

#ifdef LEAKS
  popleak(ptr);
#endif
  ret = (*func)(ptr, size);
  int pid = (int)getpid();
  fprintf(output, "%p to %p (size=%d pid=%d caller (%p))\n", ptr, ret, size, pid, callerptr);
#ifdef LEAKS
  pushleak(ret, size);
#endif
#ifdef HISTORY
  bump_counter(&rdata, size);
#endif  
*/
  return(ret);

}

void free(void * ptr)
{
/*
  STORE_CALLER_PTR(callerptr);
  static void * (*func)(void *);

  fprintf(output, "Mymalloc: free ");
  if(!func)
    *(void **) (&func) = dlsym(libc_handle, "free");

#ifdef LEAKS
  popleak(ptr);
#endif
  (*func)(ptr);
  int pid = (int)getpid();
  fprintf(output, "%p (pid=%d caller (%p))\n", ptr, pid, callerptr);
*/
}
