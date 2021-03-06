#ifndef __VERIFIER_H__
#define __VERIFIER_H__
#include <stdio.h>
#include <iostream> 
#include <fstream>
#include <sstream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include"cstdlib"
#include <functional>
#include <ctime>
#include <queue>
#include "nlohmann/json.hpp"
#include "ctcpserver.h"
#include "openssl_utils/openssl_utils.h"

//参考oracle.h
class Verifier
{
public:
	int bufSize;
	int msgSize;
    std::vector<int> generateRandNumber(int min,int max,int num);
	std::vector<int> GenerateMulList(int min,int max, int num, std::vector<int> ifList);
	std::vector<int> GenerateAddList(int min,int max, int num, std::vector<int> ifList);

	void adder(LweSample* result, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk);
	static void full_adder_MUX(LweSample *sum, const LweSample *x, const LweSample *y, const int32_t nb_bits, const TFheGateBootstrappingCloudKeySet* bk);
	static void wallace_multiplier(LweSample *result, const LweSample *lhs,  const LweSample *rhs, const int nb_bits, const TFheGateBootstrappingCloudKeySet *bk);
	void multiply(LweSample* product, LweSample* a, LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk);
	void save_maping_graph(std::vector<int> g_maping_graph, char *path, int length);
	std::vector<LweSample*> obfuscateData(int fileNUM, int obfuscatedNum,std::vector<LweSample*> cipherArray, TFheGateBootstrappingCloudKeySet* bk);
};

int run(CTcpServer TcpServer, int cfd);

#endif