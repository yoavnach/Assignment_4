all: ping traceroute port_scanning discovery tunnel

ping: ping.o
	gcc ping.o -o ping -lm

ping.o: ping.c
	gcc -c ping.c -o ping.o

traceroute: traceroute.o
	gcc traceroute.o -o traceroute

traceroute.o: traceroute.c
	gcc -c traceroute.c -o traceroute.o

port_scanning: port_scanning.o
	gcc port_scanning.o -o port_scanning

port_scanning.o: port_scanning.c
	gcc -c port_scanning.c -o port_scanning.o

discovery: discovery.o
	gcc discovery.o -o discovery

discovery.o: discovery.c
	gcc -c discovery.c -o discovery.o

tunnel: tunnel.o
	gcc tunnel.o -o tunnel

tunnel.o: tunnel.c
	gcc -c tunnel.c -o tunnel.o

clean:
	rm -f *.o ping traceroute port_scanning discovery tunnel









	