#include "so_stdio.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#define MAX_BUFF 4096
#define PERMISSION 0644
#define SUCCESS 0
#define FERR -1
#define NO_OP -1
#define READ 0
#define WRITE 1
#define NO_EOF 1
#define TRUE 1
#define FALSE 0
#define PIPE_READ 0
#define PIPE_WRITE 1
#define STDOUT 1
#define STDIN 0

struct _so_file {
	char buffer[MAX_BUFF]; /* Buffer asociat fisierului. */
	int fd;				   /* File descriptorul. */
	int curr_buff;		   /* Cursor la primul byte nefolosit din buffer. */
	off_t curr_file;	   /* Cursorul la ultimul caracter folosit din file. */
	int dim_buff;		   /* Cata caractere am disponibile in buffer. */
	int last_op;		   /* Ultima operatie efectuata. */
	int err;			   /* Daca a aparut o eroare in urma unei operatii cu fisierul. */
	int end_file;		   /* Flag care imi spune daca am ajuns la finalul fisierului sau nu. */
	pid_t child_pid;	   /* Pid-ul procesului copil, pentru fisierele deschise cu popen. */
};

int init_file(SO_FILE *file, int fd)
{
	file->fd = fd;
	file->curr_buff = 0;
	file->curr_file = 0;
	file->dim_buff = 0;
	file->last_op = NO_OP;
	file->err = 0;
	file->end_file = FALSE;
	file->child_pid = -1;

	return SUCCESS;
}

void free_so_file(SO_FILE *stream)
{
	free(stream);
}

SO_FILE *so_fopen(const char *pathname, const char *mode)
{
	SO_FILE *file;
	int flag, fd, err;

	/* Deschide fisierul cu un unul din moduri */
	/* altfel returneaza NULL */
	if (strcmp(mode, "r") == 0)
		flag = O_RDONLY;
	else if (strcmp(mode, "r+") == 0)
		flag = O_RDWR;
	else if (strcmp(mode, "w") == 0)
		flag = O_WRONLY | O_CREAT | O_TRUNC;
	else if (strcmp(mode, "w+") == 0)
		flag = O_RDWR | O_CREAT | O_TRUNC;
	else if (strcmp(mode, "a") == 0)
		flag = O_WRONLY | O_APPEND | O_CREAT;
	else if (strcmp(mode, "a+") == 0)
		flag = O_RDWR | O_APPEND | O_CREAT;
	else
		return NULL;

	fd = open(pathname, flag, PERMISSION);

	if (fd < 0)
		return NULL;

	file = calloc(1, sizeof(SO_FILE));
	if (file == NULL)
		return NULL;

	err = init_file(file, fd);
	if (err != SUCCESS) {
		free_so_file(file);
		return NULL;
	}

	return file;
}

int so_fclose(SO_FILE *stream)
{
	int err1, err2, fd_copy;

	/* Scriu in fisier */
	/* Golesc bufferul */
	fd_copy = stream->fd;
	err1 = so_fflush(stream);
	free_so_file(stream);
	err2 = close(fd_copy);

	if (err1 < 0)
		return SO_EOF;

	if (err2 < 0)
		return SO_EOF;

	return SUCCESS;
}

int so_fileno(SO_FILE *stream)
{
	return stream->fd;
}

/* Invalidez buffer-ul */
void clear_buff(SO_FILE *stream)
{
	int i;

	for (i = 0; i < MAX_BUFF; i++)
		stream->buffer[i] = '\0';

	stream->curr_buff = 0;
	stream->dim_buff = 0;
}

int so_fflush(SO_FILE *stream)
{
	ssize_t bytes;
	int cnt = 0, rest_to_write = stream->dim_buff;

	if (stream->last_op == WRITE) {
		/* Scriu toate datele din buffer in fisier */
		while (cnt < stream->dim_buff) {
			bytes = write(stream->fd, stream->buffer + cnt, rest_to_write);
			if (bytes <= 0) {
				stream->err = SO_EOF;
				return SO_EOF;
			}

			/* Contorizez cat am citit */
			cnt += bytes;
			rest_to_write -= bytes;
			stream->curr_file += (off_t)bytes;
		}

		/* Curat bufferul */
		clear_buff(stream);

		stream->err = SUCCESS;
		return SUCCESS;
	}

	return SUCCESS;
}

int so_fseek(SO_FILE *stream, long offset, int whence)
{
	off_t err = 0;

	/* Ultima operatie este citire, invalidez */
	/* buffer-ul si mut cursorul inapoi la */
	/* ultimul byte folosit */
	if (stream->last_op == READ)
		clear_buff(stream);

	/* Ultima operatie a fost scriere */
	/* scriu in fisier */
	else if (stream->last_op == WRITE) {
		err = so_fflush(stream);
		if (err != SUCCESS) {
			stream->err = FERR;
			return FERR;
		}
	}

	err = lseek(stream->fd, offset, whence);
	stream->last_op = NO_OP;

	if (err == -1) {
		stream->err = FERR;
		return FERR;
	}

	stream->curr_file = (off_t)err;
	stream->err = SUCCESS;

	return SUCCESS;
}

long so_ftell(SO_FILE *stream)
{
	stream->curr_file += stream->curr_buff;
	return stream->curr_file;
}

size_t so_fread(void *ptr, size_t size, size_t nmemb, SO_FILE *stream)
{
	int i, cnt, actual_read = 0, rest_to_read, minimum;
	long long to_read = size * nmemb;
	int dif, bytes, rest, extent = 0;

	/* Cati bytes trebuie sa citesc din fisier */
	dif = (stream->dim_buff - stream->curr_buff) - to_read;

	if (dif >= 0) {
		/* Ii citesc pe cei pe care ii am in buffer */
		memcpy(ptr, stream->buffer + stream->curr_buff, to_read);
		stream->curr_buff += to_read;
		actual_read += to_read;
	} else {
		dif = -dif;

		/* Ii citesc pe toti disponibili din buffer */
		if ((stream->dim_buff != 0) && (stream->dim_buff != stream->curr_buff)) {
			memcpy(ptr, stream->buffer + stream->curr_buff, stream->dim_buff - stream->curr_buff);
			actual_read += stream->dim_buff - stream->curr_buff;

			stream->curr_buff = stream->dim_buff;
		}

		/* De cate ori trebuie sa aduc in buffer blocuri de 4096 bytes */
		extent = dif / MAX_BUFF;

		/* Cat aduc ultima data in buffer */
		rest = dif - extent * MAX_BUFF;

		i = 0;
		/* Aduc blocuri de MAX_BUFF in buffer din fisier */
		while (i < extent && stream->end_file != TRUE) {
			cnt = 0;
			rest_to_read = MAX_BUFF;
			while (cnt < MAX_BUFF && stream->end_file != TRUE) {
				bytes = read(stream->fd, stream->buffer + cnt, rest_to_read);
				if (bytes == 0)
					stream->end_file = TRUE;

				if (bytes < 0) {
					stream->err = FERR;
					return 0;
				}

				/* Contorizez cat am adus */
				cnt += bytes;
				rest_to_read -= bytes;
			}

			/* Scriu la adresa data */
			stream->dim_buff = cnt;
			minimum = cnt < MAX_BUFF ? cnt : MAX_BUFF;
			memcpy(ptr + actual_read, stream->buffer, minimum);
			actual_read += minimum;

			/* Memorez pozitia cursorului */
			stream->curr_file += (off_t)minimum;

			stream->curr_buff = minimum;

			i++;
		}

		if (stream->end_file != TRUE) {
			stream->dim_buff = 0;
			stream->curr_buff = 0;

			memset(stream->buffer, '\0', MAX_BUFF);

			/* Aduc si ultimul bloc */
			cnt = 0;
			rest_to_read = MAX_BUFF;

			while (cnt < rest && stream->end_file != TRUE) {
				bytes = read(stream->fd, stream->buffer + cnt, rest_to_read);
				if (bytes == 0)
					stream->end_file = TRUE;

				if (bytes < 0) {
					stream->err = FERR;
					return 0;
				}

				cnt += bytes;
				rest_to_read -= bytes;
			}

			minimum = cnt < rest ? cnt : rest;
			memcpy(ptr + actual_read, stream->buffer, minimum);
			actual_read += minimum;

			stream->dim_buff = cnt;
			stream->curr_buff = minimum;
		}
	}

	stream->last_op = READ;
	return (actual_read / size);
}

size_t so_fwrite(const void *ptr, size_t size, size_t nmemb, SO_FILE *stream)
{
	int to_write = size * nmemb;
	int actual_write = 0;
	int cnt = 0, dif, rest, extent = 0;
	int err;

	/* Cati bytes pot sa scriu in buffer */
	dif = to_write - (MAX_BUFF - stream->curr_buff);

	/* Am loc sa scriu toti bytes in buffer */
	if (dif <= 0) {
		memcpy(stream->buffer + stream->curr_buff, ptr, to_write);
		stream->curr_buff += to_write;

		if (stream->curr_buff > stream->dim_buff)
			stream->dim_buff += to_write;

		actual_write += to_write;
	} else {
		/* Nu am loc sa-i scriu pe toti deodata */
		/* scriu pana la finalul bufferului */
		memcpy(stream->buffer + stream->curr_buff, ptr, MAX_BUFF - stream->curr_buff);

		/* Verific cati mi-au mai ramas de scris */
		to_write = to_write - (MAX_BUFF - stream->curr_buff);
		actual_write += MAX_BUFF - stream->curr_buff;
		cnt = MAX_BUFF - stream->curr_buff;

		stream->curr_buff = MAX_BUFF;
		stream->dim_buff = MAX_BUFF;
		stream->last_op = WRITE;

		extent = to_write / MAX_BUFF;
		rest = to_write - extent * MAX_BUFF;

		/* Fac fflush de fiecare data cand citesc 4096 bytes */
		/* Scriu extent blocuri de 4096 bytes */
		while (extent > 0) {
			err = so_fflush(stream);
			if (err != SUCCESS) {
				stream->err = FERR;
				return 0;
			}

			/* Citesc din ptr, cat sa umplu bufferul */
			memcpy(stream->buffer, ptr + cnt, MAX_BUFF);
			cnt += MAX_BUFF;
			actual_write += MAX_BUFF;
			stream->curr_buff = MAX_BUFF;
			stream->dim_buff = MAX_BUFF;

			stream->last_op = WRITE;
			extent--;
		}

		/* Scriu ultimul bloc */
		err = so_fflush(stream);
		if (err != SUCCESS) {
			stream->err = FERR;
			return 0;
		}

		memcpy(stream->buffer, ptr + cnt, rest);
		actual_write += rest;
		stream->dim_buff = rest;
		stream->curr_buff = rest;
	}

	stream->last_op = WRITE;
	return (actual_write / size);
}

int so_fgetc(SO_FILE *stream)
{
	int bytes;

	/* Verific buffer-ul */
	/* Daca nu am nimic sau am citit tot din el */
	if (stream->dim_buff == 0 || stream->curr_buff == stream->dim_buff) {
		/* Citesc din fisier */
		/* si pun in buffer */
		bytes = read(stream->fd, stream->buffer, MAX_BUFF);
		if (bytes == 0)
			stream->end_file = TRUE;

		if (bytes <= 0) {
			stream->err = SO_EOF;
			return SO_EOF;
		}

		stream->dim_buff = bytes;
		stream->curr_buff = 0;
		/* actualizez cursorul din file */
		stream->curr_file += (off_t)bytes;
	}

	stream->last_op = READ;
	stream->err = SUCCESS;

	stream->curr_buff++;
	return (int)stream->buffer[stream->curr_buff - 1];
}

int so_fputc(int c, SO_FILE *stream)
{
	int err;

	/* Verific buffer-ul daca e plin */
	if (stream->curr_buff == MAX_BUFF) {
		/* Scriu in fisier si invalidez bufferul */
		err = so_fflush(stream);
		if (err != SUCCESS) {
			stream->err = err;
			return err;
		}
	}

	/* Scriu datele in buffer */
	stream->buffer[stream->curr_buff] = (char)c;
	/* Cresc si dimensiunea */
	if (stream->curr_buff >= stream->dim_buff)
		stream->dim_buff++;

	stream->curr_buff++;

	stream->last_op = WRITE;
	stream->err = SUCCESS;

	return c;
}

int so_feof(SO_FILE *stream)
{
	if (stream->end_file == TRUE)
		return 1;
	else
		return 0;
}

int so_ferror(SO_FILE *stream)
{
	if (stream != NULL)
		return stream->err;
	return FERR;
}

/* https://github.com/systems-cs-pub-ro/so/blob/master/labs/lab03/sol/lin/6-pipe/pipe.c */
SO_FILE *so_popen(const char *command, const char *type)
{
	SO_FILE *file = NULL;
	pid_t pid;
	int err, fds[2];
	int type_parent, type_child;

	/* Verific pentru ce mod e deschis */
	if (strcmp(type, "r") == 0) {
		type_parent = PIPE_READ;
		type_child = PIPE_WRITE;
	} else if (strcmp(type, "w") == 0) {
		type_parent = PIPE_WRITE;
		type_child = PIPE_READ;
	} else {
		return NULL;
	}

	err = pipe(fds);
	if (err != SUCCESS)
		return NULL;

	pid = fork();

	switch (pid) {
	/* Eroare */
	case -1:
		close(fds[PIPE_READ]);
		close(fds[PIPE_WRITE]);
		return NULL;

	case 0:
		/* Procesul copil */
		close(fds[type_parent]);

		/* r => duplic fds[type_child] in STDOUT */
		if (strcmp(type, "r") == 0) {
			err = dup2(fds[type_child], STDOUT);
			if (err == -1) {
				close(fds[type_child]);
				break;
			}
		}

		/* w => duplic fds[type_child] in STDIN */
		else if (strcmp(type, "w") == 0) {
			err = dup2(fds[type_child], STDIN);
			if (err == -1) {
				close(fds[type_child]);
				break;
			}
		}

		/* Se executa comanda */
		err = execlp("sh", "sh", "-c", command, NULL);
		if (err == FERR)
			return NULL;

		close(fds[type_child]);
		break;
	default:
		/* Procesul parinte */
		close(fds[type_child]);
		file = calloc(1, sizeof(SO_FILE));
		if (file == NULL)
			return NULL;

		err = init_file(file, fds[type_parent]);
		if (err != SUCCESS) {
			free_so_file(file);
			return NULL;
		}
		file->child_pid = pid;
		break;
	}
	return file;
}

int so_pclose(SO_FILE *stream)
{
	int err;
	int status;

	/* Invalidez bufferul */
	err = so_fflush(stream);
	if (err != SUCCESS)
		return FERR;
	close(stream->fd);

	/* Astept procesul copil sa se termine */
	err = waitpid(stream->child_pid, &status, 0);
	if (err == FERR) {
		free_so_file(stream);
		return FERR;
	}

	if (WIFEXITED(status))
		free_so_file(stream);
	else
		stream->err = WIFEXITED(status);

	return status;
}
