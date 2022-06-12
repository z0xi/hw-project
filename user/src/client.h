#ifndef __CLIENT_H__
#define __CLIENT_H__

#include <iostream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <sstream>
#include <cstring>
#include <string>
#include "nlohmann/json.hpp"
//ifstraem
#include <fstream>

#include <ENCRYPTO_utils/parse_options.h>
#include "client_circuit.h"
#include "ctcpclient.h"

class Client
{
public:
    int bufSize;
    int msgSize;
	// bool SocketInit(std::string ip, int port);
	// bool StartServer();
	// void DealData(int client_socket);

	// struct sockaddr_in server_addr;
	// int server_socket;
	// int opt;
    void keyGen();
    void encrypt(char *buf, int size);
    void decrypt(uint16_t* bufArray, int size);
    void initRequest();
    void initRecv();
    void runProtocol();
};

#endif