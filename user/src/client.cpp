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
    if (TcpClient.ConnectToServer("127.0.0.1", 5051) == false)
    {
        printf("TcpClient.ConnectToServer failed,exit...\n"); 
        return -1;
    }
    // user.keyGen();
    // user.encrypt(buf, sizeof(buf));
    // std::cout<< "Send cipher size"<<std::endl;
    // user.bufSize = sizeof(buf);

    std::ifstream jsonstream("client_folder/credential.json");//读入json文件
    nlohmann::json credential; //定义json j
    jsonstream >> credential;//将文件中的json数据转入j
    nlohmann::json information;
    information = credential["CredentialInformation"];

    if (TcpClient.SendFile("client_folder/cloud.key") == false) {
        perror("send fail");
    }

    FILE* secret_key = fopen("client_folder/secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);

    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = key->params;
    // std::vector<int> cipherLength;
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
        std::cout<<tmp<<std::endl;
        std::cout<<value<<std::endl;
        std::cout<<value.length()<<std::endl;
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
    for (auto item : information.items())
    {
        std::string temp = information.at(item.key());
        information[item.key()] = temp.length();
    }
    credential["CredentialInformation"] = information;
    std::cout<<credential;

    std::ofstream o("client_folder/enc_credential.json");
    o << std::setw(4) << credential << std::endl;
    if (TcpClient.SendFile("client_folder/enc_credential.json") == false) {
        perror("send fail");
    }

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
    std::cout<<"Wait for confused data"<<std::endl;

    if (TcpClient.RecvFile("client_folder/confused_data") == false) {
        perror("Recv obfuscated data fail");
    }
    std::cout<<"Recv confused data"<<std::endl;
  
    // LweSample* ciphertext = new_gate_bootstrapping_ciphertext_array(8, params);
    // FILE* cloud_data = fopen("client_folder/cloud_data","wb");
    // for(int i = 0;i < sizeof(buf); i++){
    //     for (int j=0; j<8; j++) {
    //         bootsSymEncrypt(&ciphertext[j], (buf[i]>>j)&1, key);
    //     }
    //     // export_gate_bootstrapping_ciphertext_toFile(cloud_data, ciphertext, params);
    //     for (int j=0; j<8; j++) 
    //         export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext[j], params);
    // }
    // fclose(cloud_data);
	e_role role = CLIENT;
	uint32_t bitlen = 32, nvals = 1, secparam = 128, nthreads = 1;
	uint16_t port = 7766;
	std::string address = "127.0.0.1";
	e_mt_gen_alg mt_alg = MT_OT;

	e_sharing sharing = S_BOOL;
	seclvl seclvl = get_sec_lvl(secparam);
    
    ClientOnlineProtocol run_protocol;
    // uint16_t* bufArray = new uint16_t(bufSize);
    // Client::decrypt(bufArray, bufSize);
    // run_protocol.msgArray = bufArray;
    // ClientOnlineProtocol run_protocol = new ClientOnlineProtocol();
	// test_sha1_circuit(role, address, port, seclvl, nvals, nthreads, mt_alg, sharing);
	bool success = run_protocol.runProtocolCircuit(totalSize,role, address, port, seclvl, nvals, nthreads, mt_alg, sharing);
    if (success)
    {
    printf("Finished\n");/*在屏幕上打印出来 */  
    }
    return 0;  
}  