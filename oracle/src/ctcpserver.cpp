#include "ctcpserver.h"
#include <cstdio>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#define LEN 4096
CTcpServer::CTcpServer()
{
    m_listenfd = m_clientfd = 0;// ???????????socket
}

CTcpServer::~CTcpServer()
{
    if (m_listenfd != 0) close(m_listenfd);  // ???????????socket
    if (m_clientfd != 0) close(m_clientfd);  // ???????????socket
}

bool CTcpServer::InitServer(int port)
{
    m_listenfd = socket(AF_INET, SOCK_STREAM, 0);  // ??????????socket

    struct sockaddr_in servaddr;    // ?????????????????
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;  // ßø???»…??socket??????????AF_INET
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);  // ????????????ip???
    servaddr.sin_port = htons(port);  // ???????
    int opt_val = 1;
    setsockopt(m_listenfd, IPPROTO_TCP, TCP_NODELAY, (void*)&opt_val, sizeof(opt_val));
    if (bind(m_listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0)
    {
        close(m_listenfd); m_listenfd = 0; return false;
    }
    // ??socket???????????
    if (listen(m_listenfd, 5) != 0) { close(m_listenfd); m_listenfd = 0; return false; }

    return true;
}

bool CTcpServer::Accept()
{
    if ((m_clientfd = accept(m_listenfd, 0, 0)) <= 0) return false;

    return true;
}

int CTcpServer::Accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    return accept(m_listenfd, addr, addrlen);
}

int CTcpServer::Send(const void* buf, const int buflen)
{
    return send(m_clientfd, buf, buflen, 0);
}

int CTcpServer::Recv(void* buf, const int buflen)
{
    return recv(m_clientfd, buf, buflen, 0);
}

bool CTcpServer::SendFile(const char* filename) {
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
        printf("????????\n");
    }
    fclose(fp);
    sleep(1);
    return true;
}

bool CTcpServer::SendFile(const char* filename, int cfd) {
    char strbuffer[LEN];
    FILE* fp = fopen(filename, "rb");
    if (fp == NULL) return false;
    fseek(fp, 0, SEEK_END);
    int fsize = ftell(fp);
    sprintf(strbuffer, "%d", fsize);
    send(cfd, strbuffer, LEN, 0);
    rewind(fp);
    memset(strbuffer, 0, LEN);
    int iret;
    int sum = 0;
    while ((iret = fread(strbuffer, 1, LEN, fp)) > 0) {
        sum += iret;
        send(cfd, strbuffer, iret, 0);
        memset(strbuffer, 0, LEN);
    }
    if (sum == fsize)
    {
        printf("????????\n");
    }
    fclose(fp);
    sleep(1);
    return true;
}

bool CTcpServer::RecvFile(const char* filename) {
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
            printf("????????\n");
            break;
        }
        memset(strbuffer, 0, LEN);
    }
    fclose(fp);
    return true;
}

bool CTcpServer::RecvFile(const char* filename, int cfd) {
    char strbuffer[LEN];
    FILE* fp = fopen(filename, "wb+");
    if (fp == NULL) return false;
    recv(cfd, strbuffer, LEN, 0);
    int fsize;
    sscanf(strbuffer, "%d", &fsize);
    printf("the size of file:%d\n", fsize);
    memset(strbuffer, 0, LEN);
    int iret;
    int count = 0;
    while ((iret = recv(cfd, strbuffer, LEN, 0)) > 0) {
        fwrite(strbuffer, 1, iret, fp);
        count += iret;
        if (count >= fsize) {
            // printf("????????\n");
            break;
        }
        memset(strbuffer, 0, LEN);
    }
    fclose(fp);
    return true;
}