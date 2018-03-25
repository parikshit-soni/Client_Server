CC=gcc
CFLAGS=-Wall -std=c99 -g

# UDP file sending mechanism
all : client server

# Server side program
server : Server.c
	$(CC) $(CFLAGS) Server.c -o server -lssl -lcrypto -DPACKET_TRACE

# Client side program
client : Client.c
	$(CC) $(CFLAGS) Client.c -o client -lssl -lcrypto -DPACKET_TRACE

clean :
	rm -f ./*~ client server
