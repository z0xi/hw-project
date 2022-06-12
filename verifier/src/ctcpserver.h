#pragma once
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
class CTcpServer
{
public:
    int m_listenfd;   // ��������
    int m_clientfd;   // �ͻ���socket

    CTcpServer();
    bool InitServer(int port);  // ��ʼ��
    bool Accept();  // �ȴ�����
    int Accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    int  Send(const void* buf, const int buflen);// ���ͱ���
    int  Recv(void* buf, const int buflen);// ���ձ���
    bool SendFile(const char* filename);
    bool SendFile(const char* filename, int cfd);
    bool RecvFile(const char* filename, int cfd);
    bool RecvFile(const char* filename);
    ~CTcpServer();
};

