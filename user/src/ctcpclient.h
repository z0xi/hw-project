#pragma once
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

class CTcpClient
{
public:
    int m_sockfd;

    CTcpClient();
    bool ConnectToServer(const char* serverip, const int port);// ��������
    int  Send(const void* buf, const int buflen);// ���ͱ���
    int  Recv(void* buf, const int buflen);// ���ձ���
    bool SendFile(const char* filename);// �����ļ�
    bool RecvFile(const char* filename);// �����ļ�
    ~CTcpClient();
};
