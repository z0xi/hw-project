#ifndef __ORACLE_H__
#define __ORACLE_H__
#include <stdio.h>
#include <iostream> 
#include <fstream>
#include <sstream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include"cstdlib"
#include <thread>
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
    std::vector<int> generateRandNumber(int min,int max, std::vector<int> isCipher, int num);
	std::vector<int> GenerateMulList(int min,int max, int num, std::vector<int> ifList);
	std::vector<int> GenerateAddList(int min,int max, int num, std::vector<int> ifList);

	void adder(LweSample* result, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk);
	static void full_adder_MUX(LweSample *sum, const LweSample *x, const LweSample *y, const int32_t nb_bits, const TFheGateBootstrappingCloudKeySet* bk);
	static void wallace_multiplier(LweSample *result,
                        const LweSample *lhs,
                        const LweSample *rhs,
                        const int nb_bits, /* input length */
                        const TFheGateBootstrappingCloudKeySet *bk);
	void threadMultiply(std::vector<LweSample*> &product, std::vector<LweSample*> ciphertext, std::vector<int> mulList, int threadNum, const TFheGateBootstrappingCloudKeySet* bk);
	void threadAdd(std::vector<LweSample*> &product, std::vector<LweSample*> ciphertext, std::vector<int> addList, int threadNum, const TFheGateBootstrappingCloudKeySet* bk);
	void multiply(LweSample* product, LweSample* a, LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk);
	void save_maping_graph(std::vector<int> g_maping_graph, char *path, int length);
	std::vector<LweSample*> obfuscateData(int fileNUM, std::vector<int> isCipher, int obfuscatedNum,std::vector<LweSample*> cipherArray, TFheGateBootstrappingCloudKeySet* bk);
	// void sha256Init(std::vector<int> tempAH, char* buf, int size);

};
bool run(CTcpServer TcpServer, int cfd);

#endif