#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <err.h>
#include <poll.h>

#include <common.h>

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



int main(int argc, char const *argv[]) {

	if(argc != 3){
		printf("./client <hostname> <portname>\n");
		exit(EXIT_FAILURE);
	}

	char * portname = argv[2];
	char * hostname = argv[1];

	printf("Hostname : %s\n", hostname);
	printf("Port : %s\n", portname);

	int fd = socket(AF_INET, SOCK_STREAM,0);
	if(fd == -1){
		perror("Socket");
	}
	printf("Socket descriptor: %d\n", fd);

	struct addrinfo indices;
	memset(&indices, 0, sizeof(struct addrinfo));
	indices.ai_family = AF_INET;
	indices.ai_socktype = SOCK_STREAM;
	indices.ai_flags = AI_NUMERICSERV;
	struct addrinfo* res = NULL;
	struct addrinfo* tmp = NULL;

	int error = getaddrinfo(hostname, portname, &indices, &res);
	if (error != 0) {
		errx(1, "%s", gai_strerror(error));
	}

	tmp = res;
	while (tmp != NULL) {
		if (tmp->ai_family == AF_INET && tmp->ai_socktype == SOCK_STREAM){
		struct sockaddr_in* sockptr = (struct sockaddr_in *)(tmp->ai_addr);
		struct in_addr local_adress = sockptr->sin_addr;
		printf("Trying to connect to %s on port %d\n",
			inet_ntoa(local_adress), sockptr->sin_port);

		if(-1 == connect(fd, tmp->ai_addr, tmp->ai_addrlen)){
			perror("Connect");
			exit(EXIT_FAILURE);
		}


		break;
		}
		tmp=tmp->ai_next;
	}

	//send data into socket server

	int stay = 1;

	struct pollfd fds[2];

	fds[0].fd = fd;
	fds[0].events = POLLIN;
	fds[0].revents = 0;

	fds[1].fd = STDIN_FILENO;
	fds[1].events = POLLIN;
	fds[1].revents = 0;
	
	while (stay) //listening loop
	{

		poll(fds, 2, -1);

		if(fds[1].revents & POLLIN){ //if event comes from stdin
			char str[MSG_LEN];
			fgets(str, MSG_LEN, stdin);
			for(int i = 0; i<MSG_LEN;i++){
				if(str[i] == '\n'){
					str[i] = '\0';
				}
			}
			int to_send = strlen(str);
			write_int_size(fd, (void *)&to_send);
			write_in_socket(fd, str, to_send);

			printf("Message envoye : %s (%d)\n", str, to_send);
			if(strcmp("/quit", str) == 0)
			{
				stay = 0;
			}
		}

		else if (fds[0].revents & POLLIN) { //if event comes from server
			int to_read = read_int_size(fd);
			char * rcv_msg = malloc(sizeof(char)*to_read);
			read_from_socket(fd, rcv_msg, to_read);

			printf("Message recu : %s (%d)\n", rcv_msg, to_read);
			if(strcmp("/quit", rcv_msg) == 0)
			{
				stay = 0;
			}
			free(rcv_msg);
		}
	}

	return 0;
	}
