#CROSS_COMPILE=arm-none-linux-gnueabi-
CC=gcc
AR=ar
RANLIB=ranlib
LDFLAGS=-ldl
CFLAGS=-Wall

NAME=mymalloc
MAKEFILE=Makefile

TEST=
TEST_OBJECTS=test3.o

ifeq ($(STATIC_LIBRARY),y)
TARGET=lib${NAME}.a
else
TEST+=test
TARGET=lib${NAME}.so
endif

OBJECTS=lib3.o

ifneq ($(NOTHREAD),y)
LDFLAGS+=-pthread
CFLAGS+=-pthread -D_PTHREAD -DTHREAD_SAFE
endif

#$(NAME)_CCFLAGS= -DLEAKS -DARM -DHISTORY -DTHREAD_SAFE -D_PTHREAD

CFLAGS+= $($(NAME)_CCFLAGS)

all: $(MAKEFILE) $(TARGET) $(TEST)

lib$(NAME).so: CFLAGS+=-fPIC -DPIC
lib$(NAME).so: $(OBJECTS)
	$(CROSS_COMPILE)$(CC) -g -shared -Wl,-soname,$@ -o $@ $^ $(LDFLAGS)

lib$(NAME).a: $(OBJECTS) $(MAKEFILE)
	$(CROSS_COMPILE)$(AR) -cvq $@ $^
	$(CROSS_COMPILE)$(RANLIB) $@

$(TEST): $(TEST_OBJECTS)
	$(CROSS_COMPILE)$(CC) -o $(TEST) $(TEST_OBJECTS) $(LDFLAGS)

%.o:%.c
	$(CROSS_COMPILE)$(CC) -g $(CFLAGS) -c -o $@ $<

clean:
	$(RM) $(OBJECTS) $(TEST_OBJECTS) $(TARGET) $(TEST)
