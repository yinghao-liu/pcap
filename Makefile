main:main.c
	gcc -Wall -o main main.c -lpcap
.PHONY:clean
clean:
	rm -rf *.o main
