CC=bear --append -- gcc
CFLAGS=-g3 
CFILES=proxlib.c 
CFILES_PARSLIB=parslib/parslib.final.o
OUT=proxlib

all: proxlib

proxlib: $(CFILES) $(CFILES_PARSLIB)
	$(CC) $(CFLAGS) -o $(OUT) $^

clean:
	rm -f $(OUT)

tar:
	tar -cvzf proxlib.tgz $(CFILES) README Makefile 
