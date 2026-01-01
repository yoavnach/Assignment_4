All: ping.o
	gcc ping.o -o ping
ping.o: ping.c
	gcc -c ping.c -o ping.o

clean:
	rm -f ping.o ping