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
#define BACKLOG 20

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
	FILE_ACK
};

struct message {
	int pld_len;
	char nick_sender[NICK_LEN];
	enum msg_type type;
	char infos[INFOS_LEN];
};

static char* msg_type_str[] = {
	"NICKNAME_NEW",
	"NICKNAME_LIST",
	"NICKNAME_INFOS",
	"ECHO_SEND",
	"UNICAST_SEND", 
	"BROADCAST_SEND",
	"MULTICAST_CREATE",
	"MULTICAST_LIST",
	"MULTICAST_JOIN",
	"MULTICAST_SEND",
	"MULTICAST_QUIT",
	"FILE_REQUEST",
	"FILE_ACCEPT",
	"FILE_REJECT",
	"FILE_SEND",
	"FILE_ACK"
};

struct fdChain
{
    struct pollfd pollfd;
    char nickname[NICK_LEN];
    struct fdChain * next; 
};

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

void server_response(int fd, struct message * msg, void * buf){
	write_msg_struct(fd, msg);
	write_in_socket(fd, buf, msg->pld_len);
	free(msg);
}

struct message * make_msg(int pld_len, char * nick, enum msg_type type, char * info){
	struct message * msg = (struct message *)malloc(sizeof(struct message));
	msg->pld_len = pld_len;
	strcpy(msg->nick_sender, nick);
	msg->type = type;
	strcpy(msg->infos, info);
	return msg;
}

void free_msg(struct message * msg){
	free(msg);
}

int comparePollfd(struct pollfd * pollfd1, struct pollfd * pollfd2){
    if(pollfd1->fd == pollfd2->fd){
        return 1;
    }
    else{
        return 0;
    }
}

int fdAppend(struct fdChain * ptr, struct pollfd fd){
    struct fdChain * new = (struct fdChain *)malloc(sizeof(struct fdChain));
    new->pollfd = fd;
    new->next = NULL;
    struct fdChain * current = ptr;
    while(current->next != NULL){
        current = current->next;
    }
    current->next = new;
    return 1;
}

int fdRemove(struct fdChain * ptr, struct pollfd * pollfd){
    struct fdChain * current = ptr;
    struct fdChain * before;
    while (comparePollfd(&(current->pollfd), pollfd) == 0 && current->next != NULL){
        before = current;
        current = current->next;
    }
    if (current->next == NULL && comparePollfd(&(current->pollfd), pollfd) == 0){
        return -1;
    }
    else{
        before->next = current->next;
        free(current);
        return 1;
    }
}

int fdLen(struct fdChain * ptr){
    int i = 1;
    struct fdChain * current = ptr;
    while(current->next != NULL){
        i += 1;
        current = current->next;
    }
    return i;
}

struct pollfd * fdChainGetList(struct fdChain * ptr){
    int len = fdLen(ptr);
    struct pollfd * pollfds = (struct pollfd *)malloc(sizeof(struct pollfd)*len);
    struct fdChain * current = ptr;
    int i = 0;
    do
    {
        pollfds[i].fd = current->pollfd.fd;
		pollfds[i].events = current->pollfd.events;
		pollfds[i].revents = current->pollfd.revents;
        current = current->next;
        i++;
    }while (current != NULL);
    return pollfds;
}

int checkNickname(struct fdChain * ptr, char * name){
	struct fdChain * current = ptr;
	do
	{
		if(strcmp(current->nickname, name) == 0){
			return 1;
		}
		current = current->next;
	} while (current != NULL);
	return 0;
}

int setNickname(struct fdChain * ptr, struct pollfd * pollfd, char * name){
    struct fdChain * current = ptr;
    while (comparePollfd(&(current->pollfd), pollfd) == 0 && current->next != NULL){
        current = current->next;
    }

    if(current->next == NULL && comparePollfd(&(current->pollfd), pollfd) == 0){
        return -1;
    }
    else if (comparePollfd(&(current->pollfd), pollfd)) {
        strcpy(current->nickname, name);
    }

	return 0;
}

int get_nickname(struct fdChain * ptr, struct pollfd * pollfd, char * buf){
	struct fdChain * current = ptr;
	while (comparePollfd(&(current->pollfd), pollfd) == 0 && current->next != NULL){
        current = current->next;
    }

    if(current->next == NULL && comparePollfd(&(current->pollfd), pollfd) == 0){
        return -1;
    }
    else if (comparePollfd(&(current->pollfd), pollfd)) {
        strcpy(buf, current->nickname);
    }

	return 0;
}

void get_all_nicknames(struct fdChain * ptr, char ** nicknames){
	struct fdChain * current = ptr;
	int i = 0;
	do
	{
		nicknames[i] = (char *)&current->nickname;
		current = current->next;
		i++;
	} while (current != NULL);
}

void msg_response(struct message * msg, struct pollfd * pollfd, struct fdChain * chain){
	if((strcmp(msg->nick_sender, "") == 0) && msg->type != NICKNAME_NEW){
		char * response = "please login with /nick <your pseudo>";
		int len = strlen(response);
		struct message * msg = make_msg(len, "Server", UNICAST_SEND, "");
		server_response(pollfd->fd, msg, response);
	}
	else if ((strcmp(msg->nick_sender, "") == 0) && msg->type == NICKNAME_NEW){
		if(checkNickname(chain, (msg->infos))){
			char * response = "this nickname is already taken";
			int len = strlen(response);
			struct message * msg = make_msg(len, "Server", UNICAST_SEND, "");
			server_response(pollfd->fd, msg, response);
		}

		else if (strcmp(msg->infos, "") == 0){
			char * response = "nickname can't be empty";
			int len = strlen(response);
			struct message * msg = make_msg(len, "Server", UNICAST_SEND, "");
			server_response(pollfd->fd, msg, response);
		}

		else{
			setNickname(chain, pollfd, msg->infos);
			char * response = NULL;
			response = (char *)malloc(sizeof(char)*(INFOS_LEN + 21));
			response[0]='\0'; 
			strcat(response, "Welcome on the chat ");
			strcat(response, msg->infos);
			int len = strlen(response);
			struct message * msg = make_msg(len, "Server", UNICAST_SEND, "");
			server_response(pollfd->fd, msg, response);
			free(response);
		}
	}

	else{
		switch (msg->type)
		{
		case NICKNAME_NEW:
				if(checkNickname(chain, (msg->infos))){
					char * response = "this nickname is already taken";
					int len = strlen(response);
					struct message * msg = make_msg(len, "Server", UNICAST_SEND, "");
					server_response(pollfd->fd, msg, response);
				}

				else if (strcmp(msg->infos, "") == 0){
					char * response = "nickname can't be empty";
					int len = strlen(response);
					struct message * msg = make_msg(len, "Server", UNICAST_SEND, "");
					server_response(pollfd->fd, msg, response);
				}

				else{
					setNickname(chain, pollfd, msg->infos);
					char * response = NULL;
					response = (char *)malloc(sizeof(char)*(INFOS_LEN + 20));
					response[0] = '\0'; 
					strcat(response, "Your new nickname is ");
					strcat(response, msg->infos);
					int len = strlen(response);
					struct message * msg = make_msg(len, "Server", UNICAST_SEND, "");
					server_response(pollfd->fd, msg, response);
					free(response);
				}
			break;
		case NICKNAME_LIST:
				{
					char ** nicknames = NULL;
					nicknames = (char **)malloc(sizeof(char *)*fdLen(chain));
					get_all_nicknames(chain, nicknames);
					char * response = NULL;
					response = (char *)malloc(sizeof(char)*((NICK_LEN+3)*256+19));
					response[0]='\0';
					strcat(response, "Online users are :");
					for(int i = 1; i<fdLen(chain);i++){
						strcat(response, "\n");
						strcat(response, "- ");
						strcat(response, nicknames[i]);
					}

					int len = strlen(response);
					struct message * msg = make_msg(len, "Server", UNICAST_SEND, "");
					server_response(pollfd->fd, msg, response);
					free(response);
					free(nicknames);
				}
			break;

		case BROADCAST_SEND:
			{
				char * msg_rcv = NULL;
				msg_rcv = (char *)malloc(sizeof(char)*msg->pld_len);
				read_from_socket(pollfd->fd, msg_rcv, msg->pld_len);
				struct fdChain * current = chain;
				current = current->next;
				struct message * n_msg = make_msg(msg->pld_len, msg->nick_sender, BROADCAST_SEND, "");
				do
				{
					if(strcmp(current->nickname, msg->nick_sender) != 0){
						write_msg_struct(current->pollfd.fd, n_msg);
						write_in_socket(current->pollfd.fd, msg_rcv, msg->pld_len);
					}
					current = current->next;
				} while (current != NULL);
				free(msg_rcv);
			}
			break;
		
		default:
			break;
		}
	}
}

void fdChain_update(struct fdChain * chain, struct pollfd * pollfds){
	struct fdChain * current = chain;
	int i = 0;
	do
	{
		current->pollfd = pollfds[i];
		current = current->next;
		i++;
	} while (current != NULL);
	
}

int socket_listen_and_bind(char *port) {
	int listen_fd = -1;
	if (-1 == (listen_fd = socket(AF_INET, SOCK_STREAM, 0))) {
		perror("Socket");
		exit(EXIT_FAILURE);
	}
	printf("Listen socket descriptor %d\n", listen_fd);

	int yes = 1;
	if (-1 == setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int))) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	struct addrinfo indices;
	memset(&indices, 0, sizeof(struct addrinfo));
	indices.ai_family = AF_INET;
	indices.ai_socktype = SOCK_STREAM;
	indices.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
	struct addrinfo *res, *tmp;

	int err = 0;
	if (0 != (err = getaddrinfo(NULL, port, &indices, &res))) {
		errx(1, "%s", gai_strerror(err));
	}

	tmp = res;
	while (tmp != NULL) {
		if (tmp->ai_family == AF_INET) {
			struct sockaddr_in *sockptr = (struct sockaddr_in *)(tmp->ai_addr);
			struct in_addr local_address = sockptr->sin_addr;
			printf("Binding to %s on port %hd\n",
						 inet_ntoa(local_address),
						 ntohs(sockptr->sin_port));

			if (-1 == bind(listen_fd, tmp->ai_addr, tmp->ai_addrlen)) {
				perror("Binding");
			}
			if (-1 == listen(listen_fd, BACKLOG)) {
				perror("Listen");
			}
			return listen_fd;
		}
		tmp = tmp->ai_next;
	}
	return listen_fd;
}

void server(int listen_fd) {

    struct pollfd listen_pollfd;
    listen_pollfd.fd = listen_fd;
    listen_pollfd.events = POLLIN;
    listen_pollfd.revents = 0;

    char * server_listening_name = "Server_listening_port";

    struct fdChain * connexions = (struct fdChain *)malloc(sizeof(struct fdChain));
    connexions->pollfd = listen_pollfd;
	strcpy(connexions->nickname, server_listening_name);
    connexions->next = NULL;
    

	int stay = 1;

	printf("Server start\n");

	// server loop
	while (stay) {

		// Block until new activity detected on existing socket
		int n_active = 0;
        struct pollfd * pollfds = fdChainGetList(connexions);
        int nfds = fdLen(connexions);
		if (-1 == (n_active = poll(pollfds, nfds, -1))) {
			perror("Poll");
		}
		printf("[SERVER] : %d active socket\n", n_active);

		// Iterate on the array of monitored struct pollfd
		for (int i = 0; i < nfds; i++) {

			// If listening socket is active => accept new incoming connection
			if (pollfds[i].fd == listen_fd && pollfds[i].revents & POLLIN) {
				// accept new connection and retrieve new socket file descriptor
				struct sockaddr client_addr;
				socklen_t size = sizeof(client_addr);
				int client_fd;
				if (-1 == (client_fd = accept(listen_fd, &client_addr, &size))) {
					perror("Accept");
				}

				// display client connection information
				struct sockaddr_in *sockptr = (struct sockaddr_in *)(&client_addr);
				struct in_addr client_address = sockptr->sin_addr;
				printf("Connection succeeded and client used %s:%hu \n", inet_ntoa(client_address), ntohs(sockptr->sin_port));

				// store new file descriptor in available slot in the array of struct pollfd set .events to POLLIN

                struct pollfd n_pollfd = {client_fd, POLLIN, 0};
                fdAppend(connexions, n_pollfd);

				char * nick_text = "please login with /nick <your pseudo>";

				struct message * msg = make_msg(strlen(nick_text), "Server",UNICAST_SEND, "" );

				write_msg_struct(n_pollfd.fd, msg);
				write_in_socket(n_pollfd.fd, nick_text, msg->pld_len);

				free_msg(msg);

				// Set .revents of listening socket back to default
				pollfds[i].revents = 0;

			} else if (pollfds[i].fd != listen_fd && pollfds[i].revents & POLLHUP) { // If a socket previously created to communicate with a client detects a disconnection from the client side
				// display message on terminal
				printf("client on socket %d has disconnected from server\n", pollfds[i].fd);
				// Close socket and set struct pollfd back to default
				close(pollfds[i].fd);
				pollfds[i].events = 0;
				pollfds[i].revents = 0;
				fdRemove(connexions, &pollfds[i]);
			} 
			
			else if (pollfds[i].fd != listen_fd && pollfds[i].revents & POLLNVAL){
				char name[NICK_LEN];
				get_nickname(connexions, &pollfds[i], name);
				printf("%s has disconnected from server\n", name);
				close(pollfds[i].fd);
				pollfds[i].events = 0;
				pollfds[i].revents = 0;
				fdRemove(connexions, &pollfds[i]);
			}
			
			else if (pollfds[i].fd != listen_fd && pollfds[i].revents & POLLIN) { // If a socket different from the listening socket is active
				// read data from socket
				struct message * msg_rcv = (struct message *)malloc(sizeof(struct message));
				read_msg_struct(pollfds[i].fd, msg_rcv);
				msg_response(msg_rcv, &pollfds[i], connexions);
				
				// Set activity detected back to default
				pollfds[i].revents = 0;
			}
		}

        free(pollfds);
	}
}

int main(int argc, char const *argv[]) {

	// Test argc
	if (argc != 2) {
		printf("Usage: ./server port_number\n");
		exit(EXIT_FAILURE);
	}

	// Create listening socket
	char *port = (char *)argv[1];
	int listen_fd = -1;
	if (-1 == (listen_fd = socket_listen_and_bind(port))) {
		printf("Could not create, bind and listen properly\n");
		return 1;
	}
	// Handle new connections and existing ones
	server(listen_fd);

	return 0;
}