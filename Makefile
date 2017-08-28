main:main.c
	gcc -g -o main main.c -lpcap
.PHONY:clean
clean:
	rm -rf *.o main
