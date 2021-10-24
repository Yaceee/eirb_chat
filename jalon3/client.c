#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <err.h>
#include <poll.h>

#define NICK_LEN 128
#define INFOS_LEN 128
#define MSG_LEN 1024

enum msg_type { 
	NICKNAME_NEW,
	NICKNAME_LIST,
	NICKNAME_INFOS,
	ECHO_SEND,
	UNICAST_SEND, 
	BROADCAST_SEND,
	MULTICAST_CREATE,
	MULTICAST_LIST,
	MULTICAST_JOIN,
	MULTICAST_SEND,
	MULTICAST_QUIT,
	FILE_REQUEST,
	FILE_ACCEPT,
	FILE_REJECT,
	FILE_SEND,
	FILE_ACK,
    USER_QUIT,
	SERV_ERROR
};

struct message {
	int pld_len;
	char nick_sender[NICK_LEN];
	enum msg_type type;
	char infos[INFOS_LEN];
};

char * nickname = NULL;
char * room = NULL;

//Fonctions

int write_msg_struct(int fd, struct message * msg){
	int ret = 0, offset = 0, size = sizeof(struct message);
	while (offset != size) {
		if (-1 == (ret = write(fd, msg + offset, size - offset))) {
			perror("Writing from client socket");
			return -1;
		}
		offset += ret;
	}
	return offset;
}

int read_msg_struct(int fd, void * buf){
	int size = sizeof(struct message);
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

struct message * make_msg(int pld_len, char * nick, enum msg_type type, char * info){
	struct message * msg = (struct message *)malloc(sizeof(struct message));
	msg->pld_len = pld_len;
	strcpy(msg->nick_sender, nick);
	msg->type = type;
	strcpy(msg->infos, info);
	return msg;
}

int command_exec(char * str, int fd, char * nickname){
	if(str[0] == '/'){
		char * cmd = strtok(str, " ");
		if(strcmp("/nick", cmd) == 0){
			char * arg = strtok(NULL, " ");
			if(arg != NULL){
				struct message * msg = make_msg(0, nickname, NICKNAME_NEW, arg);
				write_msg_struct(fd, msg);
				free(msg);
			}
			else{
				printf("Enter a nickname as argument\n");
			}
		}

		else if(strcmp("/who", cmd) == 0){
			struct message * msg = make_msg(0,nickname,NICKNAME_LIST, "");
			write_msg_struct(fd,msg);
			free(msg);
		}

		else if(strcmp("/msgall", cmd) == 0){
			char * arg = NULL;
			arg = (char *)malloc(512);
			memset(arg, '\0', 512);
			char * token = strtok(NULL, " ");
			strcat(arg,token);
			token = strtok(NULL, " ");
			while (token != NULL)
			{
				strcat(arg, " ");
				strcat(arg,token);
				token = strtok(NULL, " ");
			}
			
			int len = strlen(arg);
			struct message * msg = make_msg(len, nickname, BROADCAST_SEND,"");
			write_msg_struct(fd,msg);
			write_in_socket(fd, arg, len);
			free(msg);
			free(arg);
		}

		else if(strcmp("/msg", cmd) == 0){
			char * dest = strtok(NULL, " ");
			char * arg = NULL;
			arg = (char *)malloc(512);
			memset(arg, '\0', 512);
			char * token = strtok(NULL, " ");
			strcat(arg,token);
			token = strtok(NULL, " ");
			while (token != NULL)
			{
				strcat(arg, " ");
				strcat(arg,token);
				token = strtok(NULL, " ");
			}
			
			int len = strlen(arg);
			printf("Msg to %s : %s\n", dest, arg);
			struct message * msg = make_msg(len, nickname, UNICAST_SEND,dest);
			write_msg_struct(fd,msg);
			write_in_socket(fd, arg, len);
			free(msg);
			free(arg);
		}

		else if(strcmp("/quit", cmd) == 0){
			struct message * msg;
			if(strcmp(room, "general") == 0){
				msg = make_msg(0,nickname,USER_QUIT, "");
			}
			else{
				msg = make_msg(0,nickname,MULTICAST_QUIT, "");
			}
			write_msg_struct(fd,msg);
			free(msg);
			return 0;
		}

		else if(strcmp("/create", cmd) == 0){
			char * arg = strtok(NULL, " ");
			if(arg != NULL){
				struct message * msg = make_msg(0, nickname, MULTICAST_CREATE, arg);
				write_msg_struct(fd, msg);
				free(msg);
			}
			else{
				printf("Enter a channel as argument\n");
			}
		}

		else if(strcmp("/join", cmd) == 0){
			char * arg = strtok(NULL, " ");
			if(arg != NULL){
				struct message * msg = make_msg(0, nickname, MULTICAST_JOIN, arg);
				write_msg_struct(fd, msg);
				free(msg);
			}
			else{
				printf("Enter a channel as argument\n");
			}
		}

		else if (strcmp("/channel_list", cmd) == 0){
			struct message * msg = make_msg(0, nickname, MULTICAST_LIST, "");
			write_msg_struct(fd, msg);
			free(msg);
		}

		else{
			printf("Commande non reconnu\n");
		}
	}
	else{
		struct message * msg = make_msg(strlen(str), nickname, MULTICAST_SEND, room);
		write_msg_struct(fd, msg);
		write_in_socket(fd, str, strlen(str));
		printf("\033[1F\033[2K");
		printf("[%s][%s] : %s\n", room, nickname, str);

		free(msg);
	}

    return 1;
}


//main

int main(int argc, char const *argv[])
{
    if(argc != 3){
		printf("./client <hostname> <portname>\n");
		exit(EXIT_FAILURE);
	}

	printf("\033[2J");
	printf("\033[H");

	char * portname = (char *)argv[2];
	char * hostname = (char *)argv[1];

	
	nickname = (char *)malloc(sizeof(char)*NICK_LEN);
    memset(nickname, '\0', NICK_LEN);

	room = (char *)malloc(sizeof(char)*NICK_LEN);
	sprintf(room, "general");

    printf("Connecting to server %s on port %s ...", hostname, portname);

	int fd = socket(AF_INET, SOCK_STREAM,0);
	if(fd == -1){
		perror("Socket");
	}

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

		if(-1 == connect(fd, tmp->ai_addr, tmp->ai_addrlen)){
			perror("Connect");
			exit(EXIT_FAILURE);
		}


		break;
		}
		tmp=tmp->ai_next;
	}

    printf("done !\n");


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
			
			command_exec(str, fds[0].fd, nickname);

		}

		else if (fds[0].revents & POLLIN) { //if event comes from server
			struct message * msg = (struct message *)malloc(sizeof(struct message));
			read_msg_struct(fds[0].fd, msg);
			char * rcv_msg = NULL;
			rcv_msg = (char *)malloc(sizeof(char)*msg->pld_len);
            memset(rcv_msg, '\0', msg->pld_len);
			read_from_socket(fd, rcv_msg, msg->pld_len);


			printf("[%s][%s] : %s\n",room , msg->nick_sender, rcv_msg);
			

            if(msg->type == USER_QUIT){
                stay = 0;
            }
			else if(msg->type == MULTICAST_JOIN){
				strcpy(room, msg->infos);
			}
			else if(msg->type == NICKNAME_NEW){
				strcpy(nickname, msg->infos);
			}
            memset(rcv_msg, '\0', msg->pld_len);
			free(rcv_msg);
			free(msg);
		}
	}

	free(nickname);
	free(room);
    
    return 0;
}