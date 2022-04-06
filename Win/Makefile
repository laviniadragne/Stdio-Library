# https://github.com/systems-cs-pub-ro/so/blob/master/labs/lab01/sol/win/3-bounds/Makefile.dynamic
CC = cl
L = link
CFLAGS = /nologo /W3 /MD /D_CRT_SECURE_NO_WARNINGS /DDLL_EXPORTS

build: so_stdio.dll

so_stdio.lib: so_stdio.dll

so_stdio.dll: so_stdio.obj
	$(L) /nologo /dll /out:$@ /implib:so_stdio.lib $**

so_stdio.obj: so_stdio.c
	$(CC) $(CFLAGS) /c $**

clean:
	del /Q /F *.obj *.lib *.dll *.exp