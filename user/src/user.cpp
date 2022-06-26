#include <fstream>
#include <iostream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <sstream>
#include <cstring>
#include <string>
#include "nlohmann/json.hpp"
//ifstraem
#include <fstream>
#include "ctcpclient.h"
#include "openssl_utils/openssl_utils.h"

void save_maping_graph(uint16_t*  g_maping_graph, char *path, int length)
{
	std::ofstream fp(path, std::ios::trunc);//只写文件 + trunc若文件存在则删除后重建
	//std::fstream fp(path, std::ios::out | std::ios::trunc);//只写文件 + trunc若文件存在则删除后新建
 
	if (!fp.is_open())
	{
		printf("can't open file\n");
		return;
	}
	for (int i = 0; i < length; i++)
	{
		fp << g_maping_graph[i];
		fp << " ";
	}
	fp.close();
}

void decrypt(uint16_t* bufArray,int bufSize){

    FILE* secret_key = fopen("client_folder/secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
	const TFheGateBootstrappingParameterSet* params = key->params;
    fclose(secret_key);
	FILE* answer_data = fopen("client_folder/verifier_confused_data","rb");
	LweSample* confused_data = new_gate_bootstrapping_ciphertext_array(16, params);
    std::cout<<bufSize<<std::endl;
	for(int j = 0;j < bufSize;j++){
        for (int i=0; i<16; i++) 
            import_gate_bootstrapping_ciphertext_fromFile(answer_data, &confused_data[i], params);
        uint16_t answer = 0;
        for (int i=0; i<16; i++) {
          int ai = bootsSymDecrypt(&confused_data[i], key)>0;
          answer |= (ai<<i);
        }
		bufArray[j] = answer;
        // std::cout<<answer<<" "<<std::endl;
    }
	fclose(answer_data);
}

int main(int argc, char **argv)  
{  
    CTcpClient TcpClient;
    // 请求连接
    if (TcpClient.ConnectToServer("127.0.0.1", 5052) == false)
    {
        printf("User.ConnectToServer failed,exit...\n"); 
        return -1;
    }

    printf("Connected\n");  

    if (TcpClient.SendFile("client_folder/cloud.key") == false) {
        perror("send fail");
    }
    if (TcpClient.SendFile("client_folder/to_v_attr.json") == false) {
        perror("send fail");
    }
    printf("Wait for confused data\n");  

    std::ifstream jsonstream("client_folder/to_v_attr.json");
    nlohmann::json attrs;
    jsonstream >> attrs;
    int attrsLength = 0 ;

    nlohmann::json enc_credential;
    FILE* secret_key = fopen("client_folder/secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);

    for (auto item : attrs.items())
    {
        std::string temp = attrs.at(item.key());
        attrsLength += temp.length();
    }
    // // just for debug
    // for (auto item : attrs.items())
    // {
    //     std::string temp = attrs.at(item.key());
    //     attrsLength += temp.length();
    //     std::stringstream attribute;
    //     LweSample* c = new_gate_bootstrapping_ciphertext_array(8, key->params);

    //     for(int i = 0;i < temp.length(); i++){
    //         for (int j=0; j<8; j++) {
    //             bootsSymEncrypt(&c[j], (temp.c_str()[i]>>j)&1, key);
    //         }
    //         // export_gate_bootstrapping_ciphertext_toFile(cloud_data, ciphertext, params);
    //         for (int j=0; j<8; j++) 
    //             export_gate_bootstrapping_ciphertext_toStream(attribute, &c[j], key->params);
    //     }
    //     // std::cout << attribute.str() << std::endl;
    //     char * enc_attr_base64 = Base64Encode(attribute.str().c_str(), attribute.str().length(), 0);
    //     enc_credential[item.key()] = enc_attr_base64;
    // }
    // std::ofstream o("client_folder/enc_credential_v.json");
    // o << std::setw(4) << enc_credential << std::endl;
    // if (TcpClient.SendFile("client_folder/enc_credential_v.json") == false) {
    //     perror("send fail");
    // }

    if (TcpClient.RecvFile("client_folder/verifier_confused_data") == false) {
        perror("Recv obfuscated data fail");
    }
    std::cout<<"Recv confused data"<<std::endl;
    uint16_t* bufArray= new uint16_t[attrsLength];
    decrypt(bufArray,attrsLength);

    save_maping_graph(bufArray, "client_folder/decrypted_confused_data", attrsLength);
    if (TcpClient.SendFile("client_folder/decrypted_confused_data") == false) {
        perror("Recv obfuscated data fail");
    }

    printf("Finished\n");

    return 0;  
}  