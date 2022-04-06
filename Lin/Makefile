CC = gcc
CFLAGS = -g -Wall -Wextra -fPIC
SFLAG = -shared

build: libso_stdio.so

libso_stdio.so: so_stdio.o
	$(CC) $(SFLAG) so_stdio.o -o libso_stdio.so -L.

so_stdio.o: so_stdio.c
	$(CC) $(CFLAGS) so_stdio.c -c -o so_stdio.o

clean:
	rm -f *.o libso_stdio.so