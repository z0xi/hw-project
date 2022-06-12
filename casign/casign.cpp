#include <iostream>
#include <cstring> 
#include "openssl_utils/openssl_utils.h"
//https://blog.csdn.net/u011341856/article/details/108797920
#include "nlohmann/json.hpp"
//ifstraem
#include <fstream>
int main(void) {

    // Windows下需要更换文件位置
    std::string pub_filename = "./openssl_utils/rsa_public_key.pem";
    std::string pri_filename = "./openssl_utils/rsa_private_key.pem";

    std::ifstream jsontest("./test.json");//读入json文件
    nlohmann::json information; //定义json j
    jsontest >> information;//将文件中的json数据转入j
    nlohmann::json credential;
    // std::string str = information.dump();
    std::string str = "";
    for (auto item : information.items())
    {
        str += item.key();
        str += information.at(item.key());
    }
    std::cout<<"str:"<< str<<std::endl;
    str = sha256(str);
    std::cout<< "hash:";
    std::cout<< str<<std::endl;

    // 私钥文件加密，公钥文件，公钥文件验证签名,解密
    std::vector<char> signature = EncryptByPrikeyFile(str, pri_filename);
    char * signature_base64 = Base64Encode(signature.data(), signature.size(), 0);
	std::cout << "Base64 Encoded:" << signature_base64 << std::endl;
 
	std::string signatureToDigest = signature_base64;
    int digest_size;
	char * digest = Base64Decode(&digest_size, (char *)signatureToDigest.c_str(), signatureToDigest.length(), 0);
	std::cout << "Base64 Decoded:" <<  digest << std::endl;

    std::cout << DecryptByPubkeyFile(digest, digest_size, pub_filename)
                << std::endl;
    //verify
    std::cout << DecryptByPubkeyFile(signature.data(), signature.size(), pub_filename)
            << std::endl;

    credential["CredentialInformation"] = information;
    credential["Issuer"] = "JNU";
    credential["HashAlgorithm"] = "SHA256";
    credential["SignatureAlforithm"] = "RSA";
    credential["Signature"] = signature_base64;
    std::cout<<credential;

    std::ofstream o("credential.json");
    o << std::setw(4) << credential << std::endl;
    return 0;
}
