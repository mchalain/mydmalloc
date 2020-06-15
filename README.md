# mydmalloc

Simple library to check malloc and free.

## build and run on Linux

```bash
$ make
$ LD_PREALOD=./libmymalloc.so ./test
```
To have more traces:
```bash
$ LD_PREALOD=./libmymalloc.so MALLOC_PRINT_ALL=1 ./test
```
To check memory overflow
```bash
$ LD_PREALOD=./libmymalloc.so MALLOC_CHECKOVERFLOW=1 ./test
```

## build and integrate on RTOS

Before check the use of threads and how to lock some parts of code.
Create a file with the definition of the functions:

 * void myd_mutex_init(void);
 * void myd_lock(void);
 * void myd_unlock(void);
 * void myd_mutex_destroy(void);

```bash
$ make STATIC_LIBRARY=y EXTERNAL_MUTEX=y
```

or use `NOTHREAD=y` at the build command

```bash
$ make STATIC_LIBRARY=y NOTHREAD=y
```
To use the library, change all memory allocation calls like:

 * malloc -> myd_malloc
 * calloc -> myd_calloc
 * realloc -> myd_realloc
 * free -> myd_free

and add the call to the functions:

 * myd_init();
 * myd_exit();
