#include "ctcpclient.h"
#include <cstdio>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#define LEN 4096
CTcpClient::CTcpClient()
{
    m_sockfd = 0;  // ���캯����ʼ��m_sockfd
}

CTcpClient::~CTcpClient()
{
    if (m_sockfd != 0) close(m_sockfd);  // ���������ر�m_sockfd
}

// ��������������ӣ�serverip-�����ip��portͨ�Ŷ˿�
bool CTcpClient::ConnectToServer(const char* serverip, const int port)
{
    m_sockfd = socket(AF_INET, SOCK_STREAM, 0); // �����ͻ��˵�socket
    struct hostent* h; // ip��ַ��Ϣ�����ݽṹ
    if ((h = gethostbyname(serverip)) == 0)
    {
        close(m_sockfd); m_sockfd = 0; return false;
    }
    // �ѷ������ĵ�ַ�Ͷ˿�ת��Ϊ���ݽṹ
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    memcpy(&servaddr.sin_addr, h->h_addr, h->h_length);
    int opt_val = 1;
    setsockopt(m_sockfd, IPPROTO_TCP, TCP_NODELAY, (void*)&opt_val, sizeof(opt_val));
    // �������������������
    if (connect(m_sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0)
    {
        close(m_sockfd); m_sockfd = 0; return false;
    }

    return true;
}

int CTcpClient::Send(const void* buf, const int buflen)
{
    return send(m_sockfd, buf, buflen, 0);
}

int CTcpClient::Recv(void* buf, const int buflen)
{
    return recv(m_sockfd, buf, buflen, 0);
}

bool CTcpClient::SendFile(const char* filename) {
    char strbuffer[LEN];
    FILE* fp = fopen(filename, "rb");
    if (fp == NULL) return false;
    fseek(fp, 0, SEEK_END);
    int fsize = ftell(fp);
    sprintf(strbuffer, "%d", fsize);
    Send(strbuffer, LEN);
    rewind(fp);
    memset(strbuffer, 0, LEN);
    int iret;
    int sum = 0;
    while ((iret = fread(strbuffer, 1, LEN, fp)) > 0) {
        sum += iret;
        Send(strbuffer, iret);
        memset(strbuffer, 0, LEN);
    }
    if (sum == fsize)
    {
        printf("����ɹ���\n");
    }
    fclose(fp);
    sleep(1);
    return true;
}

bool CTcpClient::RecvFile(const char* filename) {
    char strbuffer[LEN];
    FILE* fp = fopen(filename, "wb+");
    if (fp == NULL) return false;
    Recv(strbuffer, LEN);
    int fsize;
    sscanf(strbuffer, "%d", &fsize);
    printf("the size of file:%d\n", fsize);
    memset(strbuffer, 0, LEN);
    int iret;
    int count = 0;
    while ((iret = Recv(strbuffer, LEN)) > 0) {
        fwrite(strbuffer, 1, iret, fp);
        count += iret;
        if (count >= fsize) {
            printf("����ɹ���\n");
            break;
        }
        memset(strbuffer, 0, LEN);
    }
    fclose(fp);
    return true;
}