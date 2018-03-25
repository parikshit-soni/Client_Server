CC=gcc
CFLAGS=-Wall -std=c99 -g

# TCP file sending mechanism
all : client server

# Server side program
server : Server.c
	$(CC) $(CFLAGS) Server.c -o server -lcrypto -lssl

# Client side program
client : Client.c
	$(CC) $(CFLAGS) Client.c -o client -lcrypto -lssl

clean :
	rm -f ./*~ chksum client server
