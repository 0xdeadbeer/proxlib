CC=bear --append -- gcc
CFLAGS= -g3 -Wall -Werror

all: proxlib

proxy: proxlib.c
	$(CC) $(CFLAGS) -o proxlib.o -c proxlib.c
	$(CC) $(CFLAGS) -o proxlib proxlib.o

clean:
	rm -f proxlib *.o

tar:
	tar -cvzf proxlib.tgz proxlib.c proxlib.h README Makefile 
