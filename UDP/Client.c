#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <openssl/md5.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>

#include <sys/time.h>

int main(int argc, char *argv[]) {

  /* Check number of arguments. */
  if( argc != 4 ) {
    fprintf(stderr, "Usage : %s <hostname> <port> <filename>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  /* Parameter variables. */
  char *hostname = argv[1];
  unsigned short int port_no = atoi(argv[2]);

  /* Create socket. */
  int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if( sock_fd < 0 ) {
    perror("socket");
    exit(EXIT_FAILURE);
  }

  /* Get server's DNS entry */
  struct hostent * server = gethostbyname(hostname);
  if( server == NULL ) {
    fprintf(stderr, "Lookup failed.");
    exit(EXIT_FAILURE);
  }

  /* Build server's socket address */
  struct sockaddr_in server_address;
  memset((char *)&server_address, 0, sizeof(server_address));
  server_address.sin_family = AF_INET;
  memcpy((char*)&server_address.sin_addr.s_addr,*server->h_addr_list,server->h_length);
  server_address.sin_port = htons(port_no);

  /* Open file that needs to be sent. */
  FILE* input_fp = fopen(argv[3], "rb");
  if( input_fp == NULL ) {
    perror("fopen");
    exit(EXIT_FAILURE);
  }

  /* Get file size. */
  struct stat file_stats;
  stat(argv[3], &file_stats);
  size_t file_size = file_stats.st_size;

  /* Declare constants. */
  const size_t BUFSIZE = 1<<10, PACKET_SIZE = 1<<10,
    SEQ_SIZE = 4, LEN_SIZE = 4, BLOCK_SIZE = PACKET_SIZE - SEQ_SIZE - LEN_SIZE;

  /* Create buffer. */
  char buff[BUFSIZE];

  sprintf(buff, "%s\n%ld\n", argv[3], file_size);

  printf("Sending : [%s] (%ld)\n", argv[3], file_size);
  fflush(stdout);

  socklen_t socklen = sizeof(server_address);
  size_t bytes_written = sendto(sock_fd, buff, strlen(buff), 0,
				(struct sockaddr*) &server_address, socklen);
  if( bytes_written < 0 ) {
    perror("sendto");
    exit(EXIT_FAILURE);
  }

  /* Recieve file name and size acknowledge. */
  int bytes_read = recvfrom(sock_fd, buff, BLOCK_SIZE, 0,
			    (struct sockaddr*) &server_address, &socklen);
  if( bytes_read < 0 ) {
    perror("sendto");
    exit(EXIT_FAILURE);
  }

  printf("Acknowledged file name and size. \n");
  fflush(stdout);

  /* Set recieve timeout to 1 second after acknowledgement. */
  struct timeval timo;
  timo.tv_sec = 1; timo.tv_usec = 0;
  if( setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &timo, sizeof(timo)) < 0 ){
    perror("setsockopt");
    exit(EXIT_FAILURE);
  }

  int bytes_left = file_size;
  int chunks_transmitted = 0;

  /* Create an MD5 context. */
  MD5_CTX md5_context;
  MD5_Init(&md5_context);

  /* Transfer entire file  using stop and wait protocol.
     Generate hash simultaneously. */
  while( bytes_left > 0 ) {

    /* Generate packet. */
    bytes_read = fread(buff + SEQ_SIZE + LEN_SIZE, 1, BLOCK_SIZE, input_fp);
    if( bytes_read < 0 ) {
      perror("fopen");
      exit(EXIT_FAILURE);
    }

    /* Update hash. */
    MD5_Update(&md5_context, buff + SEQ_SIZE + LEN_SIZE, bytes_read);

    int *ptr = (int*)(buff + SEQ_SIZE);
    *ptr = bytes_read;
    ptr = (int*) buff;
    *ptr = chunks_transmitted;

#ifdef PACKET_TRACE
    fprintf(stderr, "Packet #%d generated.\n", chunks_transmitted);
    fflush(stderr);
#endif

    bytes_left -= bytes_read;

    do { /* Keep sending packets */
      bytes_written = sendto(sock_fd, buff, PACKET_SIZE, 0,
			     (struct sockaddr*) &server_address, socklen);
      if( bytes_written < 0 ) {
	perror("sendto");
	exit(EXIT_FAILURE);
      }

      int ack_sequence;
      /* Wait for acknowledgment till timeout. */
      if( recvfrom(sock_fd, &ack_sequence, SEQ_SIZE, 0,
		   (struct sockaddr*) &server_address, &socklen) >= 0 ) {
	if( ack_sequence == chunks_transmitted )
	  break;
      } else {
#ifdef PACKET_TRACE
	fprintf(stderr, "Chunk #%d : timeout.\n", chunks_transmitted);
	fflush(stderr);
#endif
      }
    } while( 1 );

#ifdef PACKET_TRACE
    fprintf(stderr, "Chunk #%d transmitted. %d bytes left. \n",
	    chunks_transmitted, bytes_left);
    fflush(stderr);
#endif

    ++chunks_transmitted;
  }

  /* Close input file. */
  fclose(input_fp);

  /* Final hash. */
  char gen_hash[MD5_DIGEST_LENGTH], rcv_hash[MD5_DIGEST_LENGTH];
  MD5_Final((unsigned char*)gen_hash, &md5_context);

  bytes_read = recvfrom(sock_fd, rcv_hash, MD5_DIGEST_LENGTH, 0,
			(struct sockaddr*) &server_address, &socklen);
  if( bytes_read < 0 ) {
    perror("recvfrom");
    exit(EXIT_FAILURE);
  }

  /* Match hashes. */
  if( bcmp(gen_hash, rcv_hash, MD5_DIGEST_LENGTH) != 0 ) {
    fprintf(stderr, "MD5 checksum did not match. Please try retransmitting.");
    fflush(stderr);
    exit(EXIT_FAILURE);
  }

  /* Print checksum. */
  printf("File transmitted successfully.\nMD5 : ");
  for(size_t i=0; i < MD5_DIGEST_LENGTH; i++)
    printf("%02x", (unsigned char)gen_hash[i]);
  printf("\n");
  fflush(stdout);

  /* Close socket. */
  close(sock_fd);

  /* Exit successfully */
  exit(EXIT_SUCCESS);
}
