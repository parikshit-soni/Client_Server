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

  if( argc != 2 ) {
    fprintf(stderr, "Usage : %s <port_no>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  unsigned short port_no = atoi(argv[1]);
  int parent_sock_fd;

  parent_sock_fd = socket(AF_INET, SOCK_STREAM, 0);
  if( parent_sock_fd < 0 ) {
    perror("socket");
    exit(EXIT_FAILURE);
  }

  /* setsockopt : Reuse address */
  int optval = 1;
  setsockopt(parent_sock_fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &optval, sizeof(int));

  /* Build server's (self) socket address */
  struct sockaddr_in server_address;
  memset((char *)&server_address, 0, sizeof(server_address));
  // bzero((char*)&server_address, sizeof server_address);
  server_address.sin_family = AF_INET;
  server_address.sin_addr.s_addr = htonl(INADDR_ANY);
  server_address.sin_port = htons((unsigned short) port_no);

  /* bind : associate parent socket with a port */
  if( bind(parent_sock_fd, (struct sockaddr*) &server_address, sizeof(server_address)) < 0 ) {
    perror("bind");
    exit(EXIT_FAILURE);
  }

  /* listen : set up this socket to accept connection requests */
  if( listen(parent_sock_fd, 5) < 0 ) {
    perror("listen");
    exit(EXIT_FAILURE);
  }
  printf("Server is listening @ %d ...\n", port_no);

  /* Prepare to recieve data. Create a separate port for listening. */
  struct sockaddr_in client_address;
  socklen_t client_len = sizeof(client_address);
  while( 1 ) {

    int child_sock_fd = accept(parent_sock_fd, (struct sockaddr*) &client_address, &client_len);
    if( child_sock_fd < 0 ) {
      perror("accept");
      exit(EXIT_FAILURE);
    }

    pid_t pid;
    if( (pid = fork()) < 0 ) {
      perror("fork");
      exit(EXIT_FAILURE);
    }

    if( pid == 0){

      char * host_addr_str = inet_ntoa(client_address.sin_addr);
      if( host_addr_str == NULL ) {
	perror("inet_ntoa");
	exit(EXIT_FAILURE);
      }

      printf("Server connected to %s...\n", host_addr_str);
      fflush(stdout);

      /* Make space to read */
      const size_t BUFSIZE = 1<<16;
      char buff[BUFSIZE];
      ssize_t bytes_read = read(child_sock_fd, buff, BUFSIZE);
      if( bytes_read < 0 ) {
	perror("read");
	exit(EXIT_FAILURE);
      }

      /* Get the filename. */
      char filename[100];
      size_t filesize, remaining_size;
      sscanf(buff, "%[^\n]\n%ld\n", filename, &filesize);

      /* Echo the read message. */
      printf("Expecting file %s sized %ld bytes from %s.\nEchoing back...\n",
	     filename, filesize, host_addr_str);
      fflush(stdout);

      write(child_sock_fd, buff, bytes_read);

      /* Open a file to write into. */
      FILE* outfile = fopen(filename, "wb");

      /* Read file in chunks of BUFSIZE. Generate md5sum simultaneously. */
      remaining_size = filesize;
      MD5_CTX md5_context;
      MD5_Init(&md5_context);
      while( remaining_size > 0 ) {
	bytes_read = read(child_sock_fd, (unsigned char*)buff, BUFSIZE);
	if( bytes_read < 0 ) {
	  perror("read");
	  exit(EXIT_FAILURE);
	}
	remaining_size -= bytes_read;
	ssize_t bytes_written = fwrite(buff, sizeof *buff, bytes_read, outfile);
	if( bytes_written < 0 ) {
	  perror("fwrite");
	  exit(EXIT_FAILURE);
	}
	MD5_Update(&md5_context, buff, bytes_written);
      }
      /* Close the copied file. */
      fclose(outfile);
      /* Get final hash. */
      unsigned char mdbuf[MD5_DIGEST_LENGTH];
      MD5_Final(mdbuf, &md5_context);
      char genbuf[1 + MD5_DIGEST_LENGTH * 2];
      for(size_t i=0; i < MD5_DIGEST_LENGTH; i++)
	sprintf(genbuf + i + i, "%02x", mdbuf[i]);
      genbuf[2 * MD5_DIGEST_LENGTH] = 0;

      /* Print file retrieval confirmation and md5 hash to terminal. */
      printf("File recieved...\nMD5 : %s\n", genbuf);
      fflush(stdout);

      /* Send back hash. */
      printf("Sending back hash...\n");
      fflush(stdout);

      write(child_sock_fd, genbuf, 2 * MD5_DIGEST_LENGTH);
      close(child_sock_fd);
      exit(EXIT_SUCCESS);

    }

    /* Close created socket in parent process. */
    close(child_sock_fd);
  }

  /* Close parent socket. */
  close(parent_sock_fd);

  /* Exit successfully */
  exit(EXIT_SUCCESS);
}
