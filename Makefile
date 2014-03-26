all: my_dns_client

my_dns_client: my_dns_client.c
	gcc -o my_dns_client -Wall my_dns_client.c

clean:
	rm -f *.o *~
	rm -f my_dns_client


