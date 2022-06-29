#include "client.h"

// Client::Client(){}

void 
Client::encrypt(char *buf, int bufSize){

    FILE* secret_key = fopen("client_folder/secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);
    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = key->params;

    LweSample* ciphertext = new_gate_bootstrapping_ciphertext_array(8, params);
    FILE* cloud_data = fopen("client_folder/cloud_data","wb");
    for(int i = 0;i < bufSize; i++){
        for (int j=0; j<8; j++) {
            bootsSymEncrypt(&ciphertext[j], (buf[i]>>j)&1, key);
        }
        // export_gate_bootstrapping_ciphertext_toFile(cloud_data, ciphertext, params);
        for (int j=0; j<8; j++) 
            export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext[j], params);
    }
    fclose(cloud_data);
}

//parse options
int32_t 
read_test_options(int32_t* argcp, char*** argvp, e_role* role, uint32_t* bitlen, uint32_t* nvals,
		uint32_t* secparam, std::string* address, uint16_t* port, e_sharing* sharing) {

	uint32_t int_role = 1, int_port = 0, int_sharing = 0;
	bool useffc = false;

	parsing_ctx options[] = { { (void*) &int_role, T_NUM, "r", "Role: 0/1", true, false }, { (void*) nvals, T_NUM, "n", "Number of parallel operation elements", false, false }, {
			(void*) bitlen, T_NUM, "b", "Bit-length, default 32", false, false }, { (void*) secparam, T_NUM, "s", "Symmetric Security Bits, default: 128", false, false }, {
			(void*) address, T_STR, "a", "IP-address, default: localhost", false, false }, { (void*) &int_port, T_NUM, "p", "Port, default: 7766", false, false }, {
			(void*) &int_sharing, T_NUM, "g", "Sharing in which the SHA1 circuit should be evaluated [0: BOOL, 1: YAO], default: BOOL", false, false } };

	if (!parse_options(argcp, argvp, options, sizeof(options) / sizeof(parsing_ctx))) {
		print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
		std::cout << "Exiting" << std::endl;
		exit(0);
	}

	assert(int_role < 2);
	*role = (e_role) int_role;

	if (int_port != 0) {
		assert(int_port < 1 << (sizeof(uint16_t) * 8));
		*port = (uint16_t) int_port;
	}

	assert(int_sharing == S_BOOL || int_sharing == S_YAO);
	assert(int_sharing != S_ARITH);
	*sharing = (e_sharing) int_sharing;

	//delete options;

	return 1;
}


void
Client::decrypt(uint16_t* bufArray,int bufSize){
    
    FILE* secret_key = fopen("client_folder/secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
	const TFheGateBootstrappingParameterSet* params = key->params;
    fclose(secret_key);
	FILE* answer_data = fopen("client_folder/confused_data","rb");
	LweSample* confused_data = new_gate_bootstrapping_ciphertext_array(16, params);

	for(int j = 0;j < bufSize;j++){
        for (int i=0; i<16; i++) 
        import_gate_bootstrapping_ciphertext_fromFile(answer_data, &confused_data[i], params);
        uint16_t answer = 0;
        for (int i=0; i<16; i++) {
          int ai = bootsSymDecrypt(&confused_data[i], key)>0;
          answer |= (ai<<i);
        }
		bufArray[j] = answer;
        // printf("%d ",answer);
    }
	fclose(answer_data);
}

void
Client::keyGen(){
    //generate a keyset
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    //generate a random key
    uint32_t seed[] = { 314, 1592, 657 };
    tfhe_random_generator_setSeed(seed,3);
    TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);

    //export the secret key to file for later use
    FILE* secret_key = fopen("client_folder/secret.key","wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
    fclose(secret_key);

    //export the cloud key to a file (for the cloud)
    FILE* cloud_key = fopen("client_folder/cloud.key","wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
    fclose(cloud_key);
    printf("keyGen finish\n");
}

int main(int argc, char **argv)  
{  
    CTcpClient TcpClient;
    Client user;
    // 请求连接
    std::cout<<"Connect server"<<std::endl;
    if (TcpClient.ConnectToServer("127.0.0.1", 5051) == false)
    {
        printf("TcpClient.ConnectToServer failed,exit...\n"); 
        return -1;
    }
    // user.keyGen();
    // user.encrypt(buf, sizeof(buf));
    std::cout<<"Step1: Initializaiton"<<std::endl;
    std::cout<<"---Key generation(NO)"<<std::endl;
    std::ifstream jsonstream("client_folder/credential.json");
    nlohmann::json credential;
    jsonstream >> credential;
    nlohmann::json information;
    information = credential["CredentialInformation"];


    FILE* secret_key = fopen("client_folder/secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);
    const TFheGateBootstrappingParameterSet* params = key->params;


    std::cout<<"---FHEencrypt"<<std::endl;
    //提取credential.json中属性值，记录每个属性值的字符数，加密属性值并保存
    int len_of_attr = information.size();
    int cipherLength[20]={0};
    uint32_t totalSize =0 ;
    int i = 1;
    for (auto item : information.items())
    {
        char tmp[30];
        std::string name = item.key();
        std::string value = information.at(item.key());
        cipherLength[i++] = value.length();
        // cipherLength.push_back(value.length());
        std::sprintf(tmp,"./client_folder/%s", item.key().c_str());
        // std::cout<<tmp<<std::endl;
        // std::cout<<value<<std::endl;
        // std::cout<<value.length()<<std::endl;
        totalSize += value.length();
        totalSize += name.length();
        LweSample* c = new_gate_bootstrapping_ciphertext_array(8, params);
        FILE* attribute = fopen(tmp,"wb");
        for(int i = 0;i < value.length(); i++){
            for (int j=0; j<8; j++) {
                bootsSymEncrypt(&c[j], (value.c_str()[i]>>j)&1, key);
            }
            // export_gate_bootstrapping_ciphertext_toFile(cloud_data, ciphertext, params);
            for (int j=0; j<8; j++) 
                export_gate_bootstrapping_ciphertext_toFile(attribute, &c[j], params);
        }
        fclose(attribute);
    }

    //创建enc_credential.json记录每个属性字段得长度，发送server端
    for (auto item : information.items())
    {
        std::string temp = information.at(item.key());
        information[item.key()] = temp.length();
    }
    credential["CredentialInformation"] = information;
    // std::cout<<credential;
    std::ofstream o("client_folder/enc_credential.json");
    o << std::setw(4) << credential << std::endl;

    std::cout<<"---Send public key"<<std::endl;
    if (TcpClient.SendFile("client_folder/cloud.key") == false) {
        perror("send fail");
    }
    if (TcpClient.SendFile("client_folder/enc_credential.json") == false) {
        perror("send fail");
    }

    //按照enc_credential.json中顺序发送属性密文
    for (auto item : information.items())
    {
        char tmp[30];
        std::string name = item.key();
        int value = information.at(item.key());
        cipherLength[i++] = value;
        // cipherLength.push_back(value.length());
        std::sprintf(tmp,"./client_folder/%s", item.key().c_str());
        if (TcpClient.SendFile(tmp) == false) {
            perror("send fail");
        }
    }
    
    std::cout<<"---Send encrypted certificate"<<std::endl;
    std::cout<<"------Wait for confused data"<<std::endl;

    //接收混淆值
    if (TcpClient.RecvFile("client_folder/confused_data") == false) {
        perror("Recv obfuscated data fail");
    }
    std::cout<<"---Recv confused data"<<std::endl;
    std::cout<<"---FHEdec"<<std::endl;
    std::cout<<"Step2: Boolean circuit running"<<std::endl;
	e_role role = CLIENT;
	uint32_t bitlen = 32, nvals = 1, secparam = 128, nthreads = 1;
	uint16_t port = 7766;
	std::string address = "127.0.0.1";
	e_mt_gen_alg mt_alg = MT_OT;

	e_sharing sharing = S_BOOL;
	seclvl seclvl = get_sec_lvl(secparam);
    
    ClientOnlineProtocol run_protocol;
	bool success = run_protocol.runProtocolCircuit(totalSize,role, address, port, seclvl, nvals, nthreads, mt_alg, sharing);
    if (success)
    {
        printf("---Success\n");/*在屏幕上打印出来 */  
    }
    return 0;  
}  