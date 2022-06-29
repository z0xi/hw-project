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
    // std::cout<<bufSize<<std::endl;
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
    std::cout<<"============================================"<<std::endl;

    std::cout<<"Connect verifier"<<std::endl;
    if (TcpClient.ConnectToServer("127.0.0.1", 5052) == false)
    {
        printf("User.ConnectToServer failed,exit...\n"); 
        return -1;
    }
    std::cout<<"Step1: Initalization"<<std::endl; 
    std::cout<<"---Send public key"<<std::endl; 
    if (TcpClient.SendFile("client_folder/cloud.key") == false) {
        perror("send fail");
    }

    std::cout<<"---Send the claim"<<std::endl; 
    if (TcpClient.SendFile("client_folder/to_v_attr.json") == false) {
        perror("send fail");
    }
    std::cout<<"------Wait for confused data"<<std::endl;


    //to_v_attr.json接收自用户前端，为用户的claim，提供给verifier用于与链上属性进行对比
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

    //接收verifier混淆值并解密
    std::cout<<"---Recv confused data"<<std::endl; 
    if (TcpClient.RecvFile("client_folder/verifier_confused_data") == false) {
        perror("Recv obfuscated data fail");
    }
    std::cout<<"Step2: Decryption"<<std::endl;
    std::cout<<"---Decrypt confused data"<<std::endl; 
    uint16_t* bufArray= new uint16_t[attrsLength];
    decrypt(bufArray,attrsLength);

    save_maping_graph(bufArray, "client_folder/decrypted_confused_data", attrsLength);

    //返回verifier解密后的混淆值
    std::cout<<"---Send decrypted data back"<<std::endl; 
    if (TcpClient.SendFile("client_folder/decrypted_confused_data") == false) {
        perror("Recv obfuscated data fail");
    }
    std::cout<<"---Finish"<<std::endl;

    return 0;  
}  