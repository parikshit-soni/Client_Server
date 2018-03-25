#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/md5.h>

#include <sys/socket.h>
#include <netdb.h>

#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char *argv[]) {

  /* Check number of arguments. */
  if( argc != 2 ) {
    fprintf(stderr, "Usage : %s <port_no>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  /* Port no on which server is running. */
  unsigned short port_no = atoi(argv[1]);

  /* Create UDP socket. */
  int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if( sock_fd < 0 ) {
    perror("socket");
    exit(EXIT_FAILURE);
  }

  /* setsockopt : Reuse address */
  int optval = 1;
  setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &optval, sizeof(int));

  /* Build server's (self) socket address */
  struct sockaddr_in server_address;
  memset((char *)&server_address, 0, sizeof(server_address));
  server_address.sin_family = AF_INET;
  server_address.sin_addr.s_addr = htonl(INADDR_ANY);
  server_address.sin_port = htons((unsigned short) port_no);

  /* bind : associate socket with a port */
  if( bind(sock_fd, (struct sockaddr*) &server_address, sizeof(server_address)) < 0 ) {
    perror("bind");
    exit(EXIT_FAILURE);
  }

  printf("Server listening @ port %d.\n", port_no);
  fflush(stdout);

  /* Declare constants. */
  const size_t BUFSIZE = 1<<10, PACKET_SIZE = 1<<10,
    SEQ_SIZE = 4, LEN_SIZE = 4, BLOCK_SIZE = PACKET_SIZE - SEQ_SIZE - LEN_SIZE;

  /* Create buffer. */
  char buff[BUFSIZE];

  /* Read from some client. */
  struct sockaddr_in client_address;
  socklen_t socklen = sizeof(client_address);

  /* Get host address. */
  char * host_address_str = inet_ntoa(client_address.sin_addr);
  if( host_address_str == NULL ) {
    perror("inet_ntoa");
    exit(EXIT_FAILURE);
  }

  /* Read and parse file name and size. */
  ssize_t bytes_read = recvfrom(sock_fd, buff, BLOCK_SIZE, 0,
				(struct sockaddr*) &client_address, &socklen);
  char filename[100];
  size_t file_size;
  sscanf(buff, "%[^\n]\n%ld\n", filename, &file_size);

  printf("Recieved : [%s] (%ld)\nEchoing back...\n", filename, file_size);
  fflush(stdout);

  /* Send back initial ACK. */
  sendto(sock_fd, buff, bytes_read, 0,
	 (struct sockaddr*) &client_address, socklen);

  /* Open file to write. */
  FILE* output_fp = fopen(filename, "wb");
  if( output_fp == NULL ) {
    perror("fopen");
    exit(EXIT_FAILURE);
  }

  int bytes_left = file_size;
  int chunks_recieved = 0;

  /* Create an MD5 context. */
  MD5_CTX md5_context;
  MD5_Init(&md5_context);

  /* Recieve entire file using stop and wait protocol. */
  while( bytes_left > 0 ) {

    /* Get next packet. */
    int sequence_number, packet_length;
    bytes_read = recvfrom(sock_fd, buff, PACKET_SIZE, 0,
			  (struct sockaddr*) &client_address, &socklen);
    if( bytes_read < 0 ) {
      perror("recvfrom");
      exit(EXIT_FAILURE);
    }
    sequence_number = *((int*)buff);
    packet_length = *((int*)(buff + SEQ_SIZE));

#ifdef PACKET_TRACE
    fprintf(stderr, "Recieved packet. Echoing back ACK%d\n", sequence_number);
    fflush(stderr);
#endif

    /* Send back acknowledgement either way. */
    sendto(sock_fd, &sequence_number, sizeof(sequence_number), 0,
	   (struct sockaddr*) &client_address, socklen);

    if( sequence_number != chunks_recieved )
      continue; /* Ignore. Packet already recieved.*/

    bytes_left -= packet_length;

    /* Write to file. */
    if( fwrite(buff + SEQ_SIZE + LEN_SIZE, 1, packet_length, output_fp) < 0 ) {
      perror("fwrite");
      exit(EXIT_FAILURE);
    }

    /* Update hash. */
    MD5_Update(&md5_context, buff + SEQ_SIZE + LEN_SIZE, packet_length);

    printf("Chunk #%d written to file. %d bytes left.\n", chunks_recieved, bytes_left);
    fflush(stdout);

    ++chunks_recieved;
  }

  /* Final hash. */
  char gen_hash[MD5_DIGEST_LENGTH];
  MD5_Final((unsigned char*)gen_hash, &md5_context);

  printf("%ld bytes recieved.\nMD5 : ", file_size);
  for(size_t i=0; i < MD5_DIGEST_LENGTH; i++)
    printf("%02x", (unsigned char) gen_hash[i]);
  printf("\n");
  fflush(stdout);

  /* Acknowledge hash. */
  int bytes_written = sendto(sock_fd, gen_hash, MD5_DIGEST_LENGTH, 0,
			     (struct sockaddr*) &client_address, socklen);
  if( bytes_written < 0 ) {
    perror("sendto");
    exit(EXIT_FAILURE);
  }

  /* Close socket. */
  close(sock_fd);

  /* Exit successfully */
  exit(EXIT_SUCCESS);
}
