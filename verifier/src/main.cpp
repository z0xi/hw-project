#include "ctcpserver.h"
#include "verifier.h"
#include "stdio.h"
#include "stdlib.h"
#include <sys/stat.h>
#include "strings.h"
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/wait.h>

void wait_child(int signo)
{
    while (waitpid(0, NULL, WNOHANG) > 0);
    return;
}

int main(int argc, char *argv[])
{
    CTcpServer TcpServer;

    if (TcpServer.InitServer(5052) == false)
    {
        printf("TcpServer.InitServer(5052) failed,exit...\n"); return -1;
    }

    int lfd, cfd;
    struct sockaddr_in client;
    socklen_t len = sizeof(client);
    char buf[1024] = {0};
    int recvlen;
    pid_t pid;

    while (1) {
        //等待客户端连接
        cfd = TcpServer.Accept(lfd, (struct sockaddr *)&client, &len);
        if (cfd == -1) {
            perror("accept error");
            return -1;
        }
        printf("Client Connected\n"); 

        pid = fork();  //每次连接到一个新的客户端就创建一个子进程
        if (pid < 0) {
            perror("fork error\n");
            return -1;
        } else if (pid == 0) {
            close(lfd); //子进程不需要cfd,只有父进程需要cfd
            break;
        } else {
            close(cfd); //父进程不需要cfd,只有子进程需要cfd
            /* 解决僵尸进程 */
            signal(SIGCHLD, wait_child);
        }
    }
//https://zhuanlan.zhihu.com/p/101830826
    if (pid == 0) {
        while (1) {
            run(TcpServer, cfd);
            printf("client close...\n");
            close(cfd);
            return 0;
        }
    }

    close(lfd);
    return 0;
}