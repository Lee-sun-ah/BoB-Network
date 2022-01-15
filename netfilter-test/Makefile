all: netfilter-test

netfilter-test: netfilter-test.o
	g++ -o netfilter-test netfilter-test.o -lnetfilter_queue

netfilter-test.o: netfilter-test.c 
	gcc -c -o netfilter-test.o netfilter-test.c -lnetfilter_queue	

clean:
	rm -f netfilter-test *.o
