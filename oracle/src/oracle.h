#ifndef __ORACLE_H__
#define __ORACLE_H__
#include <stdio.h>
#include <iostream> 
#include <fstream>
#include <sstream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include"cstdlib"
#include<functional>
#include <ctime>
#include <queue>

#include <ENCRYPTO_utils/parse_options.h>
#include "nlohmann/json.hpp"
#include "oracle_circuit.h"
#include "ctcpserver.h"
class Oracle
{
public:
	int bufSize;
	int msgSize;
	// Oracle();

	//产生随机数，用于选择消息中哪些Bytes会被混淆
    std::vector<int> generateRandNumber(int min,int max, std::vector<int> isCipher, int num);
	//产生R1数组
	std::vector<int> GenerateMulList(int min,int max, int num, std::vector<int> ifList);
	//产生R2数组
	std::vector<int> GenerateAddList(int min,int max, int num, std::vector<int> ifList);

	//加法器1
	void adder(LweSample* result, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk);
	//加法器2
	void full_adder_MUX(LweSample *sum, const LweSample *x, const LweSample *y, const int32_t nb_bits, const TFheGateBootstrappingCloudKeySet* bk);
	//乘法器1
	void wallace_multiplier(LweSample *result, const LweSample *lhs,  const LweSample *rhs, const int nb_bits, const TFheGateBootstrappingCloudKeySet *bk);
	//乘法器2
	void multiply(LweSample* product, LweSample* a, LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk);
	//保存R1 R2数组
	void save_maping_graph(std::vector<int> g_maping_graph, char *path, int length);
	//对消息进行混淆的主过程
	std::vector<LweSample*> obfuscateData(int fileNUM, std::vector<int> isCipher, int obfuscatedNum,std::vector<LweSample*> cipherArray, TFheGateBootstrappingCloudKeySet* bk);
	// void sha256Init(std::vector<int> tempAH, char* buf, int size);

};

//子进程主要流程
bool run(CTcpServer TcpServer, int cfd);

#endif