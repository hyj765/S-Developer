all: sum_test

sum_test: sum.o main.o
	gcc -o sum_test sum.o main.o

main.o: sum.h main.c
	gcc -c -o main.o main.c
sum_o: sum.h sum.c
	gcc -c -o sum.o sum.c

clean:
	rm -f sum_test *.o

