// kt526  watermark=7bffe67b862fb4bebcfbf1f63080592c
/* server.c */
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#define MAXOPEN 5
#define BUFSIZE 1024

int main(int argc, char *argv[]) {

  int listenfd, connfd;
  FILE *fp;
  struct sockaddr_in server;
  
  if (argc != 3) {
    puts("Usage: server <port> <file>");
    return 1;
  }

  if ((fp=fopen(argv[2],"rb")) == 0) {
    perror("Cannot find file to serve. (23/24)");
    return 2;
  }

  

  memset(&server,0,sizeof(server));
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = htonl(INADDR_ANY);
  server.sin_port = htons(atoi(argv[1]));
  
  if ((listenfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
    perror("Cannot create server socket");
    return 3;
  }

  if (bind(listenfd, (struct sockaddr *) &server, sizeof(server)) < 0) {
    perror("Cannot open the interface.");
    return 4;
  }

  if (listen(listenfd,MAXOPEN) < 0) {
    perror("Cannot listen on the interface.");
    return 5;
  }

  for(;;) {

    if ( (connfd = accept(listenfd, (struct sockaddr *) NULL, NULL)) < 0 ) {
      perror("Error on accept of client connection.");
      return 6;
    }

    while(!feof(fp)) {
      char bytes[BUFSIZE];
      int r=0;
      int w = 0;

      r = fread(bytes,sizeof(char),BUFSIZE,fp);
      

      while(w<r) {
        int total = write(connfd,bytes,r);
        if (total < 0) {
          perror("Error writing data to client.");
          return 7;
        }
        w+=total;
      }
    }
    fseek(fp,0,SEEK_SET);
    
    close(connfd);
    
  }
    close(listenfd);
    fclose(fp);

    return 0;
}
// kt526  watermark=7bffe67b862fb4bebcfbf1f63080592c
