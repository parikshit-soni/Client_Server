#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <openssl/md5.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>

int main(int argc, char *argv[]) {

  if( argc != 4 ) {
    fprintf(stderr, "Usage : %s <hostname> <port> <filename>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  /* Open file to read input on every byte.
     Also open descriptor table entry and read file size. */
  FILE *input_fp = fopen(argv[3], "rb");
  struct stat file_stats;
  stat(argv[3], &file_stats);
  size_t file_size = file_stats.st_size;

  if( input_fp == NULL ) {
    perror("fopen");
    exit(EXIT_FAILURE);
  }

  /* Parameter variables */
  char *hostname = argv[1];
  unsigned short int port_no = atoi(argv[2]);

  /* Create socket */
  int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
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
  // bzero((char *)&server_address, sizeof server_address);
  server_address.sin_family = AF_INET;
  memcpy((char*)&server_address.sin_addr.s_addr,
	 *server->h_addr_list,
	 server->h_length);
  server_address.sin_port = htons(port_no);

  /* Connect to server */
  if( connect(sock_fd, (const struct sockaddr *)&server_address, sizeof server_address) < 0 ) {
    perror("connect");
    exit(EXIT_FAILURE);
  }

  /* Create buffer to send packet */
  const size_t BUFSIZE = 1<<16; // 64 KiB
  char buff[BUFSIZE];
  ssize_t bytes_written;

  /* Send file name as a C string, followed by size. */
  bytes_written = sprintf(buff, "%s\n%ld\n", argv[3], file_size);
  bytes_written = write(sock_fd, buff, bytes_written);

  /* Wait for acknowledgement. */
  ssize_t bytes_read = read(sock_fd, buff, bytes_written);
  printf("Acknowledged %ld bytes.\n", bytes_read);
  fflush(stdout);

  /* Write file to stream. Generate hash simultaneously. */
  MD5_CTX md5_context;
  MD5_Init(&md5_context);
  while( ( bytes_read = fread((unsigned char*)buff, sizeof *buff, BUFSIZE, input_fp) ) != 0 ) {
    if( bytes_read < 0 ) {
      perror("read");
      exit(EXIT_FAILURE);
    }
    bytes_written = write(sock_fd, buff, bytes_read);
    if( bytes_written < 0 ) {
      perror("write");
      exit(EXIT_FAILURE);
    }
    MD5_Update(&md5_context, buff, bytes_read);
  }

  /* Close file. */
  fclose(input_fp);

  /* Get final hash. */
  unsigned char mdbuf[MD5_DIGEST_LENGTH];
  MD5_Final(mdbuf, &md5_context);
  char genbuf[1 + MD5_DIGEST_LENGTH * 2], rcvbuf[1 + MD5_DIGEST_LENGTH * 2];
  for(size_t i=0; i < MD5_DIGEST_LENGTH; i++)
    sprintf(genbuf + i + i, "%02x", mdbuf[i]);
  genbuf[2 * MD5_DIGEST_LENGTH] = 0;

  /* Wait for hash. */
  bytes_read = read(sock_fd, rcvbuf, 2 * MD5_DIGEST_LENGTH);
  rcvbuf[2 * MD5_DIGEST_LENGTH] = 0;

  /* Compare checksum. */
  if( strcmp(genbuf, rcvbuf) != 0 ) {
    fprintf(stderr, "Checksum did not match. Try transferring the file again.\n");
    fflush(stderr);
    exit(EXIT_FAILURE);
  }

  printf("File transferred successfully.\n");

  /* Close socket. */
  close(sock_fd);

  /* Exit successfully */
  exit(EXIT_SUCCESS);
}
