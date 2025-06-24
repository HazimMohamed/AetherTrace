testfib:
	rm -f fib.o fib
	gcc -O0 -fno-builtin -fno-inline -fno-unroll-loops -g -o fib fib.c
	-./fib