NAME=mymalloc
MAKEFILE=Makefile

TEST=test
TEST_OBJECTS=test3.o

TARGET=lib${NAME}.so
OBJECTS=lib3.o
#CC=arm-none-linux-gnueabi-gcc
CC=gcc
LDFLAGS=-ldl -pthread
#LDFLAGS=-ldl
CFLAGS=-g -fPIC -DPIC -Wall -pthread -D_PTHREAD -DTHREAD_SAFE

#${NAME}_CCFLAGS= -DLEAKS -DARM -DHISTORY -DTHREAD_SAFE -D_PTHREAD

CFLAGS+= ${${NAME}_CCFLAGS}

$(TARGET): $(OBJECTS) $(MAKEFILE)
	$(CC) -g -shared -Wl,-soname,$(TARGET) -o $(TARGET) $(OBJECTS) $(LDFLAGS)

$(TEST): $(TEST_OBJECTS) $(MAKEFILE)
	$(CC) -o $(TEST) $(TEST_OBJECTS) $(LDFLAGS)

all: clean $(TARGET) $(TEST)

clean:
	$(RM) $(OBJECTS) $(TEST_OBJECTS) $(TARGET) $(TEST)