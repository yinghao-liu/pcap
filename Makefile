main:main.c
	gcc -o main main.c -lpcap
.PHONY:clean
clean:
	rm -rf *.o main
