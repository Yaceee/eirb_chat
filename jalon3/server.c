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
	FILE_ACK,
	USER_QUIT,
	SERV_ERROR
};

struct message { //message struct préfixe
	int pld_len;
	char nick_sender[NICK_LEN];
	enum msg_type type;
	char infos[INFOS_LEN];
};

struct fdChain //liste chainée socket
{
    struct pollfd pollfd;
    char nickname[NICK_LEN];
    char room[NICK_LEN];
    struct fdChain * next; 
};

struct room //liste chainée salons de discutions
{
    char nom_room[NICK_LEN];
    int Nuser;
    struct room* next;
};


/*----- FONCTIONS -----*/

//Envoi de message


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

void server_response(int fd, struct message * msg, void * buf){ //réponse avec libération struct message 
	write_msg_struct(fd, msg);
	write_in_socket(fd, buf, msg->pld_len);
	free(msg);
}

void server_response_(int fd, struct message * msg, void * buf){ //réponse sans libération struct message
	write_msg_struct(fd, msg);
	write_in_socket(fd, buf, msg->pld_len);
}

struct message * make_msg(int pld_len, char * nick, enum msg_type type, char * info){ //revoie pointeur avec struct msg
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

//Gestions fd

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
    strcpy(new->room, "general");
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

struct pollfd * fdChainGetList(struct fdChain * ptr){ //créer un tableau pollfds à partir de la liste chainée
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

//Gestion salons

int roomAppend(struct room * ptr, char * r_name){
    struct room * new = (struct room *)malloc(sizeof(struct room));
    strcpy(new->nom_room, r_name);
    new->next = NULL;
	new->Nuser = 0;
    struct room * current = ptr;
    while(current->next != NULL){
        current = current->next;
    }
    current->next = new;
    return 1;
}

int roomRemove(struct room * ptr, char * r_name){
    struct room * current = ptr;
    struct room * before = NULL;
    do
	{
		if(strcmp(current->nom_room, r_name) == 0){
			before->next = current->next;
			return 1;
		}
		before = current;
		current = current->next;
	} while (current != NULL);
	return -1;
}

int roomLen(struct room * ptr){
    int i = 1;
    struct room * current = ptr;
    while(current->next != NULL){
        i += 1;
        current = current->next;
    }
    return i;
}

int roomExist(struct room * ptr, char * r_name){
	struct room * current = ptr;
    do{
        if(strcmp(current->nom_room, r_name) == 0){
			return 1;
		}
        current = current->next;
    }while(current != NULL);
    return 0;
}

int roomAddUser(struct room * ptr, char * room_name)
{
	struct room * current = ptr;
	do
	{
		if(strcmp(current->nom_room, room_name) == 0){
			current->Nuser = current->Nuser + 1;
			return 0; 
		}
		current = current->next;
	} while (current != NULL);

	return -1;
	
}

int roomRemoveUser(struct room * ptr, char * room_name)
{
	struct room * current = ptr;
	do
	{
		if(strcmp(current->nom_room, room_name) == 0){
			current->Nuser = current->Nuser - 1;
			if(current->Nuser == 0){
				return 1;
			}
			return 0; 
		}
		current = current->next;
	} while (current != NULL);

	return -1;
	
}

int roomChange(struct fdChain * ptr, struct pollfd * pollfd,struct room * rooms,  char * r_name, char * prev_r_name){
	struct fdChain * current = ptr;
	int last = 0;
    while (comparePollfd(&(current->pollfd), pollfd) == 0 && current->next != NULL){
        current = current->next;
    }

    if(current->next == NULL && comparePollfd(&(current->pollfd), pollfd) == 0){
        return -1;
    }
    else if (comparePollfd(&(current->pollfd), pollfd)) {
		last = roomRemoveUser(rooms, prev_r_name);
        strcpy(current->room, r_name);
		roomAddUser(rooms, r_name);
    }

	return last;
}

int roomGet(struct fdChain * ptr, char * user_name, char * buf){
	struct fdChain * current = ptr;
	while (strcmp(current->nickname, user_name) != 0 && current->next != NULL){
        current = current->next;
    }

    if(current->next == NULL && strcmp(current->nickname, user_name) != 0){
        return -1;
    }
    else if (strcmp(current->nickname, user_name) == 0) {
        strcpy(buf, current->room);
    }

	return 0;
}

void roomGetAll(struct room * ptr, char ** channels){
	struct room * current = ptr;
	int i = 0;
	do
	{
		channels[i] = (char *)&current->nom_room;
		current = current->next;
		i++;
	} while (current != NULL);
}

void roomSendAll(struct fdChain * ptr, char * msg_txt, char * r_name, char * sender_name, int pld_len){
	struct fdChain * current = ptr;
	struct message * msg = make_msg(pld_len, sender_name, MULTICAST_SEND, r_name);
	do
	{
		if(strcmp(current->room, r_name) == 0 && strcmp(current->nickname, sender_name) != 0){
			server_response_(current->pollfd.fd, msg, msg_txt);
		}
		current = current->next;
	} while (current != NULL);
	free(current);
	free(msg);
}

int roomGetNUser(struct room * ptr, char * r_name){
	struct room * current = ptr;
	do
	{
		if(strcmp(r_name, current->nom_room) == 0){
			return current->Nuser;
		}
		current = current->next;
	} while (current != NULL);
	return -1;
}

//Gestion nom utilisateur

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

//Fonction de réponse du serveur aux paquets entrant

int msg_response(struct message * msg, struct pollfd * pollfd, struct fdChain * chain, struct room * rooms){

	//si nouvel utilisateur
	if((strcmp(msg->nick_sender, "") == 0) && msg->type != NICKNAME_NEW){
		char * w_msg = (char *)malloc(sizeof(char)*38);
		strcpy(w_msg, "please login with /nick <your pseudo>");
		int len = strlen(w_msg);
		struct message * msg = make_msg(len, "Server", UNICAST_SEND, "");
		server_response(pollfd->fd, msg, w_msg);
		free(w_msg);
	}
	else if ((strcmp(msg->nick_sender, "") == 0) && msg->type == NICKNAME_NEW){
		if(checkNickname(chain, (msg->infos))){
			char * response = "this nickname is already taken";
			int len = strlen(response);
			struct message * msg = make_msg(len, "Server", SERV_ERROR, "");
			server_response(pollfd->fd, msg, response);
		}

		else if (strcmp(msg->infos, "") == 0){
			char * response = "nickname can't be empty";
			int len = strlen(response);
			struct message * msg = make_msg(len, "Server", SERV_ERROR, "");
			server_response(pollfd->fd, msg, response);
		}

		else{
			setNickname(chain, pollfd, msg->infos);
			char * response = NULL;
			response = (char *)malloc(sizeof(char)*(INFOS_LEN + 22));
			memset(response, '\0', INFOS_LEN + 22);
			strcat(response, "Welcome on the chat ");
			strcat(response, msg->infos);
			int len = strlen(response);
			struct message * resp = make_msg(len+1, "Server", NICKNAME_NEW, msg->infos);
			server_response(pollfd->fd, resp, response);
			free(response);
		}
	}
	//si utilisateur a déjà un nickname
	else{
		switch (msg->type)
		{
		case NICKNAME_NEW:
				if(checkNickname(chain, (msg->infos))){
					char * response = "this nickname is already taken";
					int len = strlen(response);
					struct message * msg = make_msg(len, "Server", SERV_ERROR, "");
					server_response(pollfd->fd, msg, response);
				}

				else if (strcmp(msg->infos, "") == 0){
					char * response = "nickname can't be empty";
					int len = strlen(response);
					struct message * msg = make_msg(len, "Server", SERV_ERROR, "");
					server_response(pollfd->fd, msg, response);
				}

				else{
					setNickname(chain, pollfd, msg->infos);
					char * response = NULL;
					response = (char *)malloc(sizeof(char)*(INFOS_LEN + 22));
					memset(response, '\0', (INFOS_LEN + 22));
					strcat(response, "Your new nickname is ");
					strcat(response, msg->infos);
					int len = strlen(response)+1;
					struct message * resp = make_msg(len, "Server", NICKNAME_NEW, msg->infos);
					server_response(pollfd->fd, resp, response);
					free(response);
				}
			break;
		case NICKNAME_LIST:
				{
					char ** nicknames = NULL;
					nicknames = (char **)malloc(sizeof(char *)*fdLen(chain));
					get_all_nicknames(chain, nicknames);
					char * response = NULL;
					response = (char *)malloc(sizeof(char)*((NICK_LEN+3)*fdLen(chain)+19));
					memset(response, '\0', ((NICK_LEN+3)*fdLen(chain)+19));
					strcat(response, "Online users are :");
					for(int i = 1; i<fdLen(chain);i++){
						strcat(response, "\n");
						strcat(response, "- ");
						strcat(response, nicknames[i]);
					}
					strcat(response, "\0");

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
				memset(msg_rcv, '\0', msg->pld_len);
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

		case UNICAST_SEND:
			{
				char * msg_rcv = NULL;
				msg_rcv = (char *)malloc(sizeof(char)*msg->pld_len);
				memset(msg_rcv, '\0', msg->pld_len);
				read_from_socket(pollfd->fd, msg_rcv, msg->pld_len);
				struct fdChain * current = chain;
				current = current->next;
				struct message * n_msg = make_msg(msg->pld_len, msg->nick_sender, UNICAST_SEND, msg->infos);
				do
				{
					if(strcmp(current->nickname, msg->infos) == 0){
						write_msg_struct(current->pollfd.fd, n_msg);
						write_in_socket(current->pollfd.fd, msg_rcv, msg->pld_len);
						break;
					}
					current = current->next;
				} while (current != NULL);

				if(current == NULL){
					char * err = "User does not exist";
					struct message * err_msg = make_msg(strlen(err), "Server", SERV_ERROR, "");
					server_response(pollfd->fd, err_msg, err);
				}
				free(n_msg);
			}
			break;

		case MULTICAST_CREATE:
			{
				if(roomExist(rooms, msg->infos) == 0){
					roomAppend(rooms, msg->infos);
					char * r_text = (char *)malloc(sizeof(char)*(26+strlen(msg->infos)));
					memset(r_text, '\0',26+strlen(msg->infos) );
					strcat(r_text, "You have created channel ");
					strcat(r_text, msg->infos);
					struct message * r_msg = make_msg(strlen(r_text), "Server", UNICAST_SEND, "");
					server_response(pollfd->fd, r_msg, r_text);
					free(r_text);

					char * actual_room = (char *)malloc(sizeof(char)*NICK_LEN);
					memset(actual_room, '\0', NICK_LEN);
					roomGet(chain, msg->nick_sender, actual_room);

					if(roomChange(chain, pollfd, rooms, msg->infos, actual_room) == 1 && strcmp(actual_room, "general") != 0){
						char * room_dlt = (char *)malloc(sizeof(char)*(NICK_LEN + 59));
						sprintf(room_dlt, "You were the last user in the channel, %s has been destroyed", actual_room);
						struct message * dst_msg = make_msg(strlen(room_dlt), "Server", UNICAST_SEND, "");
						roomRemove(rooms, actual_room);
						server_response(pollfd->fd, dst_msg, room_dlt);
						free(room_dlt);
					}
					r_text = (char *)malloc(sizeof(char)*(25+strlen(msg->infos)));
					memset(r_text, '\0', 25+strlen(msg->infos));
					strcat(r_text, "You have joined channel ");
					strcat(r_text, msg->infos);
					r_msg = make_msg(strlen(r_text), "Server", MULTICAST_JOIN, msg->infos);
					server_response(pollfd->fd, r_msg, r_text);
					free(r_text);
				}
				else{
					char * r_text = (char *)malloc(sizeof(char)*27);
					memset(r_text, '\0', 27);
					strcat(r_text, "This channel already exist");
					struct message * r_msg = make_msg(strlen(r_text), "Server", SERV_ERROR, "");
					server_response(pollfd->fd, r_msg, r_text);
					free(r_text);
				}
			}
			break;

		case MULTICAST_JOIN:
		{
			printf("%s want to join channel %s, roomExist = %i\n", msg->nick_sender, msg->infos, roomExist(rooms, msg->infos));
			if(roomExist(rooms, msg->infos) == 1){
				char * r_text = (char *)malloc(sizeof(char)*(25+strlen(msg->infos)));
				char * welcome_msg = (char *)malloc(sizeof(char)*(NICK_LEN + 20));
				memset(r_text, '\0', 25+strlen(msg->infos));
				memset(welcome_msg, '\0', NICK_LEN + 20);

				sprintf(welcome_msg, "%s have joined the channel", msg->nick_sender);
				roomSendAll(chain, welcome_msg, msg->infos, "INFO", strlen(welcome_msg));

				strcat(r_text, "You have joined channel ");
				strcat(r_text, msg->infos);

				struct message * r_msg = make_msg(strlen(r_text), "Server", MULTICAST_JOIN, msg->infos);
				server_response(pollfd->fd, r_msg, r_text);

				char * user_room_name = (char *)malloc(sizeof(char)*NICK_LEN);
				roomGet(chain, msg->nick_sender, user_room_name);
				if(roomChange(chain, pollfd, rooms, msg->infos, user_room_name) == 1 && strcmp(user_room_name, "general") != 0){
					char * room_dlt = (char *)malloc(sizeof(char)*(NICK_LEN + 59));
					sprintf(room_dlt, "You were the last user in the channel, %s has been destroyed", user_room_name);
					struct message * dst_msg = make_msg(strlen(room_dlt), "Server", UNICAST_SEND, "");
					roomRemove(rooms, user_room_name);
					server_response(pollfd->fd, dst_msg, room_dlt);
					free(room_dlt);
				}
				free(user_room_name);
				free(r_text);
				free(welcome_msg);
			}
			else{
				char * r_text = (char *)malloc(sizeof(char)*27);
				strcat(r_text, "Channel not found");
				struct message * r_msg = make_msg(strlen(r_text), "Server", SERV_ERROR, "");
				server_response(pollfd->fd, r_msg, r_text);
				free(r_text);
			}	
		}
		break;

		case MULTICAST_LIST:
		{
			char ** channels = NULL;
			channels = (char **)malloc(sizeof(char *)*roomLen(rooms));
			roomGetAll(rooms, channels);
			char * response = NULL;
			char * buf = (char *)malloc(sizeof(char)*NICK_LEN+7);
			memset(buf, '\0', NICK_LEN+7);
			response = (char *)malloc(sizeof(char)*((NICK_LEN+3)*roomLen(rooms)+15));
			memset(response, '\0', ((NICK_LEN+3)*roomLen(rooms)+15));
			strcat(response, "Channels are :");
			for(int i = 0; i<roomLen(rooms);i++){
				sprintf(buf, "\n- %s (%i)", channels[i], roomGetNUser(rooms, channels[i]));
				strcat(response, buf);
				memset(buf, '\0', NICK_LEN+7);
			}
			strcat(response, "\0");

			int len = strlen(response);
			struct message * msg = make_msg(len, "Server", UNICAST_SEND, "");
			server_response(pollfd->fd, msg, response);
			free(buf);
			free(response);
			free(channels);
		}

		break;

		case MULTICAST_QUIT:
		{
			char * user_room_name = (char *)malloc(sizeof(char)*NICK_LEN);
			roomGet(chain, msg->nick_sender, user_room_name);

			if(strcmp(user_room_name, "general") != 0){
				
				if(roomChange(chain, pollfd, rooms, msg->infos, user_room_name) == 1){
					char * room_dlt = (char *)malloc(sizeof(char)*(NICK_LEN + 59));
					sprintf(room_dlt, "You were the last user in the channel, %s has been destroyed", user_room_name);
					struct message * dst_msg = make_msg(strlen(room_dlt), "Server", UNICAST_SEND, "");
					roomRemove(rooms, user_room_name);
					server_response(pollfd->fd, dst_msg, room_dlt);
					free(room_dlt);
				}
				else{
					char * room_dlt = (char *)malloc(sizeof(char)*(NICK_LEN + 23));
					sprintf(room_dlt, "%s have left the channel", user_room_name);
					roomSendAll(chain, room_dlt, user_room_name, "INFO", strlen(room_dlt));
					free(room_dlt);
				}
				char * r_text = "You returned to channel general";
				struct message * r_msg = make_msg(strlen(r_text), "Server", MULTICAST_JOIN, "general");
				server_response(pollfd->fd, r_msg, r_text);
			}
			else{
				char * r_text = (char *)malloc(sizeof(char)*35);
				strcat(r_text, "You are already in general channel");
				struct message * r_msg = make_msg(strlen(r_text), "Server", UNICAST_SEND, "");
				server_response(pollfd->fd, r_msg, r_text);
				free(r_text);
			}
		}

		break;

		case MULTICAST_SEND:
		{
			char * msg_rcv = (char *)malloc(sizeof(char)*msg->pld_len);
			memset(msg_rcv, '\0', msg->pld_len);
			read_from_socket(pollfd->fd, msg_rcv, msg->pld_len);
			char * room_to_send = (char *)malloc(sizeof(char)*NICK_LEN);
			roomGet(chain, msg->nick_sender, room_to_send);
			roomSendAll(chain, msg_rcv, room_to_send,msg->nick_sender, msg->pld_len);
			free(msg_rcv);
			free(room_to_send);
		}

		break;

		case USER_QUIT:
			{
				char * msg_str = "Goodbye !";
				struct message * msg_rsp = make_msg(strlen(msg_str), "Server", USER_QUIT, "");
				server_response(pollfd->fd, msg_rsp, msg_str);
				return 1;
			}
			break;
		
		default:
			break;
		}
	}
	return 0;
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
    struct room * rooms = (struct room *)malloc(sizeof(struct room));
    connexions->pollfd = listen_pollfd;
	strcpy(connexions->nickname, server_listening_name);
    connexions->next = NULL;
	rooms->Nuser = 1;
	strcpy(rooms->nom_room, "general");
    

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

				char * nick_text = (char *)malloc(sizeof(char)*38);
				strcpy(nick_text, "please login with /nick <your pseudo>");

				struct message * msg = make_msg(strlen(nick_text), "Server",UNICAST_SEND, "" );

				write_msg_struct(n_pollfd.fd, msg);
				write_in_socket(n_pollfd.fd, nick_text, msg->pld_len);

				rooms->Nuser += 1; 
				free_msg(msg);
				free(nick_text);

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
				rooms->Nuser -= 1;
			} 
			
			else if (pollfds[i].fd != listen_fd && pollfds[i].revents & POLLNVAL){
				char name[NICK_LEN];
				get_nickname(connexions, &pollfds[i], name);
				printf("%s has disconnected from server\n", name);
				close(pollfds[i].fd);
				pollfds[i].events = 0;
				pollfds[i].revents = 0;
				fdRemove(connexions, &pollfds[i]);
				rooms->Nuser -= 1;
			}
			
			else if (pollfds[i].fd != listen_fd && pollfds[i].revents & POLLIN) { // If a socket different from the listening socket is active
				// read data from socket
				int state = 0;
				struct message * msg_rcv = (struct message *)malloc(sizeof(struct message));
				int readed = read_msg_struct(pollfds[i].fd, msg_rcv);
				if(readed != -1){
					state = msg_response(msg_rcv, &pollfds[i], connexions, rooms);
				}
				if(state == 1){
					pollfds[i].events = POLLHUP;
					printf("User %s is going to quit\n", msg_rcv->nick_sender);
				}
				
				// Set activity detected back to default
				pollfds[i].revents = 0;
			}
		}

        free(pollfds);
	}
	free(rooms);
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