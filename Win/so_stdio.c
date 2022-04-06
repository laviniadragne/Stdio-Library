#include "so_stdio.h"

#define DIM_MODE 3
#define MAX_COMMAND 100
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
#define PIPE_READ	0
#define PIPE_WRITE	1
#define STDOUT 1
#define STDIN 0


struct _so_file {
	char buffer[MAX_BUFF]; /* Buffer asociat fisierului. */
	HANDLE fd; /* File descriptorul. */
	int curr_buff; /* Cursor la primul byte nefolosit din buffer. */
	int curr_file; /* Cursorul in fisier. */
	int dim_buff; /* Cate caractere am disponibile in buffer. */
	int last_op; /* Ultima operatie efectuata. */
	int err; /* Daca a aparut o eroare in urma unei operatii cu fisierul. */
	int end_file; /* Flag care imi spune daca am ajuns la finalul fisierului sau nu. */
	PROCESS_INFORMATION process_popen; /* Procesul deschis la popen. */
	char mode[DIM_MODE]; /* Modul in care e deschis fisierul. */
};

int init_file(SO_FILE *file, HANDLE fd, const char *mode)
{
	file->fd = fd;
	file->curr_buff = 0;
	file->curr_file = 0;
	file->dim_buff = 0;
	file->last_op = NO_OP;
	file->err = 0;
	file->end_file = FALSE;
	memset(file->mode, 0, DIM_MODE);
	strcpy(file->mode, mode);

	return SUCCESS;
}

void free_so_file(SO_FILE *stream)
{
	free(stream);
}

SO_FILE *so_fopen(const char *pathname, const char *mode)
{
	SO_FILE *file;
	HANDLE fd;
	int err;
	long access, share, disposition;

	// Deschide fisierul cu un unul din moduri
	// altfel returneaza NULL
	if (strcmp(mode, "r") == 0) {
		access = GENERIC_READ;
		share = FILE_SHARE_READ | FILE_SHARE_WRITE;
		disposition = OPEN_EXISTING;
	} else if (strcmp(mode, "r+") == 0) {
		access = GENERIC_READ | GENERIC_WRITE;
		share = FILE_SHARE_READ | FILE_SHARE_WRITE;
		disposition = OPEN_EXISTING;
	} else if (strcmp(mode, "w") == 0) {
		access = GENERIC_WRITE;
		share = FILE_SHARE_READ | FILE_SHARE_WRITE;
		disposition = CREATE_ALWAYS;
	} else if (strcmp(mode, "w+") == 0) {
		access = GENERIC_WRITE | GENERIC_READ;
		share = FILE_SHARE_READ | FILE_SHARE_WRITE;
		disposition = CREATE_ALWAYS;
	} else if (strcmp(mode, "a") == 0) {
		access = GENERIC_WRITE;
		share = FILE_SHARE_READ | FILE_SHARE_WRITE;
		disposition = OPEN_ALWAYS;
	} else if (strcmp(mode, "a+") == 0) {
		access = GENERIC_WRITE | GENERIC_READ;
		share = FILE_SHARE_READ | FILE_SHARE_WRITE;
		disposition = OPEN_ALWAYS;
	} else {
		return NULL;
	}

	fd = CreateFile(pathname, access, share, NULL,
		disposition, FILE_ATTRIBUTE_NORMAL, NULL);

	if (fd == INVALID_HANDLE_VALUE)
		return NULL;

	file = calloc(1, sizeof(SO_FILE));
	if (file == NULL)
		return NULL;

	err = init_file(file, fd, mode);
	if (err != SUCCESS) {
		free_so_file(file);
		return NULL;
	}

	return file;
}

int so_fclose(SO_FILE *stream)
{
	int err1, err2;
	HANDLE fd_copy;

	/* Scriu in fisier */
	/* Golesc bufferul */
	fd_copy = stream->fd;
	err1 = so_fflush(stream);
	free_so_file(stream);
	err2 = CloseHandle(fd_copy);

	if (err1 < 0)
		return SO_EOF;

	if (err2 == 0)
		return SO_EOF;

	return SUCCESS;
}

HANDLE so_fileno(SO_FILE *stream)
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
	int bytes, err;
	int cnt = 0, rest_to_write = stream->dim_buff;

	if (stream->last_op == WRITE) {
		/* Scriu toate datele din buffer in fisier */
		while (cnt < stream->dim_buff) {
			/* Daca sunt in modul append */
			if (strstr(stream->mode, "a") != 0) {
				/* Ma mut la final cu cursorul */
				err = SetFilePointer(stream->fd, 0,
					NULL, FILE_END);
				if (err == INVALID_SET_FILE_POINTER) {
					stream->err = SO_EOF;
					return SO_EOF;
				}
				stream->curr_file = err;
			}
			err = WriteFile(stream->fd,
				stream->buffer + cnt,
				rest_to_write, &bytes, NULL);

			if (bytes == 0) {
				stream->err = SO_EOF;
				return SO_EOF;
			}
			if (err == 0) {
				stream->err = SO_EOF;
				return SO_EOF;
			}

			/* Contorizez cat am citit */
			cnt += bytes;
			rest_to_write -= bytes;
			stream->curr_file += bytes;
		}

		// invalidez bufferul
		clear_buff(stream);

		stream->err = SUCCESS;
		return SUCCESS;
	}

	return SUCCESS;
}

int so_fseek(SO_FILE *stream, long offset, int whence)
{
	int err = 0, dif;

	/* Ultima operatie este citire, invalidez */
	/* buffer-ul si mut cursorul inapoi la */
	/* ultimul byte folosit */
	if (stream->last_op == READ) {
		dif = stream->dim_buff - stream->curr_buff;
		clear_buff(stream);
	}

	/* Ultima operatie a fost scriere */
	/* scriu in fisier */
	else if (stream->last_op == WRITE) {
		err = so_fflush(stream);
		if (err != SUCCESS) {
			stream->err = FERR;
			return FERR;
		}
	}

	err = SetFilePointer(stream->fd, offset, NULL,
						whence);
	stream->last_op = NO_OP;

	if (err == INVALID_SET_FILE_POINTER) {
		stream->err = FERR;
		return FERR;
	}

	stream->curr_file = err;
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
	int i, cnt, actual_read = 0, rest_to_read, minimum, err;
	long to_read = size * nmemb;
	int bytes, rest, extent = 0;
	long dif;

	/* Cati bytes trebuie sa citesc din fisier */
	dif = (stream->dim_buff - stream->curr_buff) - to_read;

	if (dif >= 0) {
		/* Ii citesc pe cei pe care ii am in buffer */
		memcpy(ptr, stream->buffer + stream->curr_buff,
			to_read);
		stream->curr_buff += to_read;
		actual_read += to_read;
	} else {
		dif = -dif;
		/* Ii citesc pe toti disponibili din buffer */
		if ((stream->dim_buff != 0) &&
			(stream->dim_buff != stream->curr_buff)) {
			memcpy(ptr, stream->buffer + stream->curr_buff,
					stream->dim_buff - stream->curr_buff);
			actual_read += stream->dim_buff - stream->curr_buff;

			stream->curr_buff = stream->dim_buff;
		}

		/* De cate ori trebuie sa aduc in buffer blocuri */
		/* de 4096 bytes */
		extent = dif / MAX_BUFF;

		/* Cat aduc ultima data in buffer */
		rest = dif - extent * MAX_BUFF;

		i = 0;
		/* Aduc blocuri de MAX_BUFF in buffer din fisier */
		while (i < extent && stream->end_file != TRUE) {
			cnt = 0;
			rest_to_read = MAX_BUFF;
			while (cnt < MAX_BUFF && stream->end_file != TRUE) {
				err = ReadFile(stream->fd, stream->buffer + cnt,
					rest_to_read, &bytes, NULL);
				if (bytes == 0)
					stream->end_file = TRUE;

				if (err == 0) {
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
			memcpy((char *) ptr + actual_read, stream->buffer,
					minimum);
			actual_read += minimum;

			/* Memorez pozitia cursorului */
			stream->curr_file += minimum;

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
				err = ReadFile(stream->fd, stream->buffer + cnt,
					rest_to_read, &bytes, NULL);

				if (bytes == 0)
					stream->end_file = TRUE;

				if (err == 0) {
					stream->err = FERR;
					return 0;
				}

				cnt += bytes;
				rest_to_read -= bytes;
			}

			minimum = cnt < rest ? cnt : rest;
			memcpy((char *) ptr + actual_read,
					stream->buffer, minimum);
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
		memcpy(stream->buffer + stream->curr_buff,
				ptr, to_write);
		stream->curr_buff += to_write;
		if (stream->curr_buff > stream->dim_buff)
			stream->dim_buff += to_write;

		actual_write += to_write;
	} else {
		/* Scriu pana umplu bufferul */
		memcpy(stream->buffer + stream->curr_buff, ptr,
				MAX_BUFF - stream->curr_buff);

		/* Calculez cati bytes mi-au mai ramas bytes de scris */
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
			memcpy(stream->buffer, (char *) ptr + cnt, MAX_BUFF);
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

		memcpy(stream->buffer, (char *) ptr + cnt, rest);
		actual_write += rest;
		stream->dim_buff = rest;
		stream->curr_buff = rest;
	}

	stream->last_op = WRITE;
	return (actual_write / size);
}

int so_fgetc(SO_FILE *stream)
{
	int bytes, err;
	int cnt = 0;

	/* Verific buffer-ul */
	/* Daca nu am nimic sau am citit tot din el */
	if (stream->dim_buff == 0 ||
		stream->curr_buff == stream->dim_buff) {
		/* Citesc din fisier */
		/* si pun in buffer */
		err = ReadFile(stream->fd, stream->buffer,
			MAX_BUFF, &bytes, NULL);
		if (bytes == 0) {
			stream->end_file = TRUE;
			stream->err = SO_EOF;
			return SO_EOF;
		}

		if (err == 0) {
			stream->err = FERR;
			return FERR;
		}

		stream->dim_buff = bytes;
		stream->curr_buff = 0;
		/* actualizez cursorul din file */
		stream->curr_file += bytes;
	}

	stream->last_op = READ;
	stream->err = SUCCESS;

	stream->curr_buff++;
	return (int) stream->buffer[stream->curr_buff - 1];
}

int so_fputc(int c, SO_FILE *stream)
{
	int err;

	/* Actualizez cursorul din file */
	if (stream->curr_buff == MAX_BUFF) {
		/* Scriu in fisier si invalidez bufferul */
		err = so_fflush(stream);
		if (err != SUCCESS) {
			stream->err = err;
			return err;
		}
	}

	/* Scriu datele in buffer */
	stream->buffer[stream->curr_buff] = (char) c;
	/* Cresc numarul de caractere disponibile din buffer */
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

static VOID RedirectHandle(STARTUPINFO *psi, HANDLE hFile, INT opt)
{
	if (hFile == INVALID_HANDLE_VALUE)
		return;

	ZeroMemory(psi, sizeof(*psi));
	psi->cb = sizeof(*psi);

	psi->hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	psi->hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	psi->hStdError = GetStdHandle(STD_ERROR_HANDLE);

	psi->dwFlags |= STARTF_USESTDHANDLES;

	switch (opt) {
	case STD_INPUT_HANDLE:
		psi->hStdInput = hFile;
		break;
	case STD_OUTPUT_HANDLE:
		psi->hStdOutput = hFile;
		break;
	case STD_ERROR_HANDLE:
		psi->hStdError = hFile;
		break;
	}
}

SO_FILE *so_popen(const char *command, const char *type)
{
	SO_FILE *file = NULL;
	int err;
	int type_parent, type_child;
	char exec_command[MAX_COMMAND];
	HANDLE fds[2];
	SECURITY_ATTRIBUTES sa;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	memset(exec_command, 0, MAX_COMMAND);
	strcpy(exec_command, "cmd /C ");
	strcat(exec_command, command);

	ZeroMemory(&sa, sizeof(sa));
	sa.bInheritHandle = TRUE;

	ZeroMemory(&pi, sizeof(pi));
	ZeroMemory(&si, sizeof(si));

	if (strcmp(type, "r") == 0) {
		type_parent = PIPE_READ;
		type_child = PIPE_WRITE;
	} else if (strcmp(type, "w") == 0) {
		type_parent = PIPE_WRITE;
		type_child = PIPE_READ;
	} else {
		return NULL;
	}

	err = CreatePipe(&fds[PIPE_READ], &fds[PIPE_WRITE],
		&sa, 0);

	if (err == 0)
		return NULL;

	file = calloc(1, sizeof(SO_FILE));
	if (file == NULL)
		return NULL;

	err = init_file(file, fds[type_parent], type);
	if (err != SUCCESS) {
		free_so_file(file);
		return NULL;
	}


	if (strcmp(type, "r") == 0) {
		/* Redirectez outputul */
		RedirectHandle(&si, fds[PIPE_WRITE],
		STD_OUTPUT_HANDLE);
	} else if (strcmp(type, "w") == 0) {
		/* Redirectez inputul */
		RedirectHandle(&si, fds[PIPE_READ],
		STD_INPUT_HANDLE);
	}

	err = SetHandleInformation(fds[type_parent],
		HANDLE_FLAG_INHERIT, 0);

	if (err == FALSE) {
		CloseHandle(fds[PIPE_READ]);
		CloseHandle(fds[PIPE_WRITE]);
		free_so_file(file);
		return NULL;
	}

	err = CreateProcess(NULL, exec_command, NULL, NULL,
		TRUE, 0, NULL, NULL, &si, &pi);

	if (err == FALSE) {
		CloseHandle(fds[type_child]);
		CloseHandle(fds[type_parent]);
		free_so_file(file);
		return NULL;
	}

	file->process_popen = pi;
	if (strcmp(type, "r") == 0) {
		err = CloseHandle(fds[PIPE_WRITE]);
		if (err == FALSE) {
			free_so_file(file);
			return NULL;
		}
	} else if (strcmp(type, "w") == 0) {
		err = CloseHandle(fds[PIPE_READ]);
		if (err == FALSE) {
			free_so_file(file);
			return NULL;
		}
	}

	return file;
}

int so_pclose(SO_FILE *stream)
{
	int err;
	int wait_err;
	int status = 0;

	/* Invalidez bufferul */
	err = so_fflush(stream);
	if (err != SUCCESS)
		return FERR;
	err = CloseHandle(stream->fd);
	if (err == FALSE) {
		free_so_file(stream);
		return FERR;
	}

	/* Astept procesul copil sa se termine */
	wait_err = WaitForSingleObject(stream->process_popen.hProcess,
				INFINITE);
	if (wait_err == WAIT_FAILED) {
		free_so_file(stream);
		return FERR;
	}

	err = CloseHandle(stream->process_popen.hThread);
	if (err == FALSE) {
		free_so_file(stream);
		return FERR;
	}

	err = CloseHandle(stream->process_popen.hProcess);
	if (err == FALSE) {
		free_so_file(stream);
		return FERR;
	}

	wait_err = GetExitCodeProcess(stream->process_popen.hProcess,
				&status);
	if (wait_err == 0)
		free_so_file(stream);
	else
		stream->err = status;

	return status;
}

