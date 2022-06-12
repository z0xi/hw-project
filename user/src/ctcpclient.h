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
    bool ConnectToServer(const char* serverip, const int port);// 发起连接
    int  Send(const void* buf, const int buflen);// 发送报文
    int  Recv(void* buf, const int buflen);// 接收报文
    bool SendFile(const char* filename);// 发送文件
    bool RecvFile(const char* filename);// 接收文件
    ~CTcpClient();
};
