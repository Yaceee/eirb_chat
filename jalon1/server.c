#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <err.h>

#include <common.h>

#define BACKLOG 20

void write_int_size(int fd, void *ptr) {
	int ret = 0, offset = 0;
	while (offset != sizeof(int)) {
		ret = write(fd, ptr + offset, sizeof(int) - offset);
		if (-1 == ret)
			perror("Writing size");
		offset += ret;
	}
}

int read_int_size(int fd) {
	int read_value = 0;
	int ret = 0, offset = 0;
	while (offset != sizeof(int)) {
		ret = read(fd, (void *)&read_value + offset, sizeof(int) - offset);
		if (-1 == ret)
			perror("Reading size");
		if (0 == ret) {
			printf("Should close connection, read 0 bytes\n");
			close(fd);
			return -1;
		}
		offset += ret;
	}
	return read_value;
}

int read_from_socket(int fd, void *buf, int size) {
	int ret = 0;
	int offset = 0;
	while (offset != size) {
		ret = read(fd, buf + offset, size - offset);
		if (-1 == ret) {
			perror("Reading from client socket");
			exit(EXIT_FAILURE);
		}
		if (0 == ret) {
			printf("Should close connection, read 0 bytes\n");
			close(fd);
			return -1;
			break;
		}
		offset += ret;
	}
	return offset;
}

int write_in_socket(int fd, void *buf, int size) {
	int ret = 0, offset = 0;
	while (offset != size) {
		if (-1 == (ret = write(fd, buf + offset, size - offset))) {
			perror("Writing from client socket");
			return -1;
		}
		offset += ret;
	}
	return offset;
}

int config_listening_socket(){
  int listen_fd = -1;
  if(-1 == (listen_fd = socket(AF_INET, SOCK_STREAM,0))){
    perror("Socket");
  }
  printf("Listen socket descriptor: %d\n", listen_fd);

  int yes = 1;
  if(-1 == setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int))){
    perror("setsockopt");
    exit(EXIT_FAILURE);
  }

  printf("backlog number: %d\n", BACKLOG);
  return listen_fd;
}

struct addrinfo* config_address(const char* portname){
  struct addrinfo* server_addr = NULL;
  struct addrinfo indices;
  memset(&indices, 0, sizeof(struct addrinfo));
  indices.ai_family = AF_INET;
  indices.ai_socktype = SOCK_STREAM;
  indices.ai_flags = AI_PASSIVE | AI_NUMERICSERV;


  int error = getaddrinfo(NULL, portname, &indices, &server_addr);
  if (0 != error) {
    errx(1, "%s", gai_strerror(error));
  }

  return server_addr;
}

void server_waiting_loop(struct addrinfo* server_addr, int listen_fd){
  while (server_addr != NULL) {
    if (server_addr->ai_family == AF_INET && server_addr->ai_socktype == SOCK_STREAM){
      struct sockaddr_in* sockptr = (struct sockaddr_in *)(server_addr->ai_addr);
      struct in_addr local_adress = sockptr->sin_addr;
      printf("Trying to connect to %s on port %d\n",
          inet_ntoa(local_adress), sockptr->sin_port);

      if(-1 == bind(listen_fd, server_addr->ai_addr, server_addr->ai_addrlen)){
        perror("Binding");
      }

      if(-1 == listen(listen_fd, BACKLOG)){
        perror("Listen");
      };
      break;
    }
    server_addr=server_addr->ai_next;
  }
}

int connexion(int listen_fd){
  printf("Start accepting...\n");
  struct sockaddr client_addr;
  memset(&client_addr, 0, sizeof(client_addr));
  socklen_t sock_len = sizeof(client_addr);
  int client_fd= 0;
  if(-1 == (client_fd = accept(listen_fd, &client_addr, &sock_len))){
    perror("Accept");
  }

  struct sockaddr_in *sockptr = (struct sockaddr_in*)(&client_addr);
  struct in_addr client_address = sockptr->sin_addr;
  printf("Connection succed and client info \nclient_fd = %d\n", client_fd);
  printf("Binding to %s on port %hu\n", inet_ntoa(client_address), ntohs(sockptr->sin_port));

  return client_fd;
}

int main(int argc, char const *argv[]) {

  if(argc !=2){
    printf("Usage: %s <portname>\n", argv[0]);
    exit(EXIT_FAILURE);
  }


  // configuration & connexion
  const char* portname = argv[1];
  struct addrinfo* server_addr = config_address(portname);
  int listen_fd = config_listening_socket();

  server_waiting_loop(server_addr, listen_fd);
  int client_fd = connexion(listen_fd);


  // read data from socket

    int stay = 1;

  while (stay)
  {
    int size = read_int_size(client_fd);
    char * str = malloc(size);
    read_from_socket(client_fd, (void*) str, size);

    printf("Message recu : %s\n", str);

    write_int_size(client_fd, (void *)&size);
    write_in_socket(client_fd, str, size);

    if(strcmp("/quit", str) == 0){
        stay = 0;
    }
      
    free(str);
  }
  


  close(client_fd);
  close(listen_fd);
  return 0;
}
