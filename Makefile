CC=bear --append -- gcc
CFLAGS= -g3 -Wall -Werror

all: proxy

proxy: proxy.c
	$(CC) $(CFLAGS) -o proxy.o -c proxy.c
	$(CC) $(CFLAGS) -o proxy proxy.o

clean:
	rm -f proxy *.o

tar:
	tar -cvzf ass1.tgz proxy.c README Makefile proxy_parse.c proxy_parse.h
