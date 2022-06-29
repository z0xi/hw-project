#include "oracle.h"

// Oracle::Oracle(){}

std::vector<int> 
Oracle::generateRandNumber(int min, int max, std::vector<int> isCipher, int num)
{
    std::vector<int> diff;

    std::random_shuffle(isCipher.begin(),isCipher.end());

    for(int i = 0 ; i < num ; i++)
    {
      diff.push_back(isCipher[i]);
    }
    sort(diff.begin(), diff.end());

    return diff;
}

std::vector<int> 
Oracle::GenerateMulList(int min,int max, int num, std::vector<int> ifList)
{
    int rnd;
    std::vector<int> diff;
    std::srand((unsigned)time(0)); //初始化随机数种子
    for(int i = 0,j = 0; i < num ; i++)
    {
      if(i == ifList[j]){
        rnd = min+rand()%(max-min+1);
        diff.push_back(rnd);
        j++;
      }
      else{
        diff.push_back(1);
      }
    }
    return diff;
}

std::vector<int> 
Oracle::GenerateAddList(int min,int max, int num, std::vector<int> ifList)
{
    int rnd;
    std::vector<int> diff;
    std::srand((unsigned)time(0)); //初始化随机数种子
    for(int i = 0,j = 0; i < num ; i++)
    {
      if(i == ifList[j]){
        rnd = min+rand()%(max-min+1);
        diff.push_back(rnd);
        j++;
      }
      else{
        diff.push_back(0);
      }
    }
    return diff;
}

void 
Oracle::adder(LweSample* result, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
  LweSample* tmps = new_gate_bootstrapping_ciphertext_array(4, bk->params);

  //initialize the carry to 0
  bootsCONSTANT(&tmps[0], 0, bk);
  bootsCONSTANT(&tmps[1], 0, bk);
  bootsCONSTANT(&tmps[2], 0, bk);
  bootsCONSTANT(&tmps[3], 0, bk);
  //run the elementary comparator gate n times
  for (int i=0; i<nb_bits; i++) {
      bootsXOR(&tmps[1], &a[i], &b[i], bk);
      bootsAND(&tmps[2], &a[i], &b[i], bk);
      bootsXOR(&result[i], &tmps[1], &tmps[0], bk);
      bootsAND(&tmps[3], &tmps[0], &tmps[1], bk);
      bootsOR(&tmps[0], &tmps[2], &tmps[3], bk);
  }
  delete_gate_bootstrapping_ciphertext_array(4, tmps);
}

void
multiplexer(LweSample* rdbdata,LweSample* a,LweSample* b,LweSample* select_line,const int nb_bit, const TFheGateBootstrappingCloudKeySet* bk){
    int m=0;
    for(int i=0;i<nb_bit;i++){
        bootsMUX(&rdbdata[i],&select_line[m],&b[i],&a[i],bk);
    }
}

void
Oracle::multiply(LweSample* product, LweSample* a, LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk){
        
    LweSample* enc_theta=new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    for(int i=0;i<nb_bits;i++){ //initialize theta to all zero bits
        bootsCONSTANT(&enc_theta[i],0,bk);
    }
    for(int i=0;i<2*nb_bits;i++){ //initialize product to all zero bits
        bootsCONSTANT(&product[i],0,bk);
    } 

    for (int i=0; i<nb_bits; i++) {
        LweSample* temp_result=new_gate_bootstrapping_ciphertext_array(2 * nb_bits, bk->params);
        LweSample* partial_sum=new_gate_bootstrapping_ciphertext_array(2 * nb_bits, bk->params);
        for(int j=0;j<2*nb_bits;j++){ //initialize temp_result to all zero bits
            bootsCONSTANT(&temp_result[j],0,bk);
            bootsCONSTANT(&partial_sum[j],0,bk);
        } 
        LweSample* temp2=new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
        multiplexer(temp2,enc_theta,a,&b[i],nb_bits,bk);
        for(int j=0;j<nb_bits;j++){ 
            bootsCOPY(&temp_result[i+j],&temp2[j],bk);
        }

        //Add the valid result to partial_sum//
        Oracle::full_adder_MUX(partial_sum,product,temp_result,2*nb_bits,bk);
        //Change the partial sum to final product//
        for(int j=0;j<2*nb_bits;j++){ 
            bootsCOPY(&product[j],&partial_sum[j],bk);
        }
    }
}

void
Oracle::full_adder_MUX(LweSample *sum, const LweSample *x, const LweSample *y, const int32_t nb_bits,
                    const TFheGateBootstrappingCloudKeySet* bk) {
    // carries
    LweSample *carry = new_gate_bootstrapping_ciphertext_array(2, bk->params);
      bootsCONSTANT(&carry[0], 0, bk);
  bootsCONSTANT(&carry[1], 0, bk); // first carry initialized to 0
    // temps
    LweSample *temp = new_gate_bootstrapping_ciphertext_array(2, bk->params);
    for (int32_t i = 0; i < nb_bits; ++i) {
        //sumi = xi XOR yi XOR carry(i-1) 
        bootsXOR(temp, x + i, y + i, bk); // temp = xi XOR yi
        bootsXOR(sum + i, temp, carry, bk);

        // carry = MUX(xi XOR yi, carry(i-1), xi AND yi)
        bootsAND(temp + 1, x + i, y + i, bk); // temp1 = xi AND yi
        bootsMUX(carry + 1, temp, carry, temp + 1, bk);

        bootsCOPY(carry, carry + 1, bk);
    }
    // bootsCOPY(sum + nb_bits, carry, bk);

    delete_gate_bootstrapping_ciphertext_array(2, temp);
    delete_gate_bootstrapping_ciphertext_array(2, carry);
}

void 
Oracle::wallace_multiplier(LweSample *result,
                        const LweSample *lhs,
                        const LweSample *rhs,
                        const int nb_bits, /* input length */
                        const TFheGateBootstrappingCloudKeySet *bk) {
  if (nb_bits==1) {
    bootsAND(&result[0], &lhs[0], &rhs[0], bk);
  } else {
    using T = std::tuple<int, LweSample *>;
    std::priority_queue<T, std::vector<T>, std::function<bool(const T &, const T &)>>
        elems_sorted_by_depth(
        [](const T &a, const T &b) -> bool { return std::get<0>(a) > std::get<0>(b); });

    // shift copies of rhs and AND with lhs at the same time
    for (int i = 0; i < nb_bits; ++i) {
      // take rhs, shift it by i, i.e. save to ..[j+i] and AND each bit with lhs[i]
      // then write into i-th intermediate result
      LweSample *temp = new_gate_bootstrapping_ciphertext_array(2*nb_bits, bk->params);
      for (int k = 0; k < 2*nb_bits; ++k) {
        bootsCONSTANT(&temp[k], 0, bk); //initialize all the other positions
      }
      for (int j = 0; j < nb_bits; ++j) {
        bootsAND(&temp[j + i], &lhs[i], &rhs[j], bk);
      }

      elems_sorted_by_depth.push(std::forward_as_tuple(1, temp));

    }

    while (elems_sorted_by_depth.size() > 2) {
      int da, db, dc;
      LweSample *a, *b, *c;

      std::tie(da, a) = elems_sorted_by_depth.top();
      elems_sorted_by_depth.pop();
      std::tie(db, b) = elems_sorted_by_depth.top();
      elems_sorted_by_depth.pop();
      std::tie(dc, c) = elems_sorted_by_depth.top();
      elems_sorted_by_depth.pop();

      // tmp1 = lhs ^ rhs ^ c;
      LweSample *tmp1 = new_gate_bootstrapping_ciphertext_array(2*nb_bits, bk->params);
      for (int i = 0; i < 2*nb_bits; ++i) {
        bootsXOR(&tmp1[i], &a[i], &b[i], bk);
        bootsXOR(&tmp1[i], &tmp1[i], &c[i], bk);
      }
      // Shift a, b and c 1 to the right
      // Actually, we instead later shift tmp2!
      //
      //      a >>= 1;
      //      b >>= 1;
      //      c >>= 1;

      // tmp2 = ((a ^ c) & (b ^ c)) ^c;
      LweSample *tmp2 = new_gate_bootstrapping_ciphertext_array(2*nb_bits, bk->params);
      LweSample *a_XOR_c = new_gate_bootstrapping_ciphertext_array(2*nb_bits, bk->params);
      LweSample *b_XOR_c = new_gate_bootstrapping_ciphertext_array(2*nb_bits, bk->params);
      LweSample *a_x_c_AND_b_x_c = new_gate_bootstrapping_ciphertext_array(2*nb_bits, bk->params);
      bootsCONSTANT(&tmp2[0], 0, bk); //because we do the shift during the bootsXOR
      for (int i = 0; i < 2*nb_bits; ++i) {
        bootsXOR(&a_XOR_c[i], &a[i], &c[i], bk);
        bootsXOR(&b_XOR_c[i], &b[i], &c[i], bk);
        bootsAND(&a_x_c_AND_b_x_c[i], &a_XOR_c[i], &b_XOR_c[i], bk);
        if (i < 2*nb_bits - 1) {
          bootsXOR(&tmp2[i + 1], &a_x_c_AND_b_x_c[i], &c[i], bk);
        }
      }


      delete_gate_bootstrapping_ciphertext_array(2*nb_bits, a_XOR_c);
      delete_gate_bootstrapping_ciphertext_array(2*nb_bits, b_XOR_c);
      delete_gate_bootstrapping_ciphertext_array(2*nb_bits, a_x_c_AND_b_x_c);

      elems_sorted_by_depth.push(std::forward_as_tuple(dc, tmp1));
      elems_sorted_by_depth.push(std::forward_as_tuple(dc + 1, tmp2));
    }

    int da, db;
    LweSample *a, *b;

    std::tie(da, a) = elems_sorted_by_depth.top();
    elems_sorted_by_depth.pop();
    std::tie(db, b) = elems_sorted_by_depth.top();
    elems_sorted_by_depth.pop();

    /// add final two numbers
    LweSample *carry = new_gate_bootstrapping_ciphertext(bk->params);
    bootsCONSTANT(carry, 0, bk);
    Oracle::full_adder_MUX(result, a, b, 2*nb_bits, bk);
    // ripple_carry_adder(result, carry, a, b, 2*nb_bits, bk);
  }

}

void 
Oracle::save_maping_graph(std::vector<int> g_maping_graph, char *path, int length)
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

//obfuscate data
std::vector<LweSample*>
Oracle::obfuscateData(int fileNUM, std::vector<int> isCipher, int obfuscatedNum, std::vector<LweSample*> cipherArray, TFheGateBootstrappingCloudKeySet* bk)
{
    std::vector<int> ifList = generateRandNumber(0, fileNUM, isCipher, obfuscatedNum);

    std::vector<int> randMulList = GenerateMulList(0, 127,fileNUM,ifList);

    std::vector<LweSample*> tempMul;
    std::vector<LweSample*> tempAdd;
    LweSample* constant = new_gate_bootstrapping_ciphertext_array(16, bk->params);
    for(int i =0; i < fileNUM; i++){
        for(int j =0; j < 16; j++)
          bootsCONSTANT(&constant[j], (randMulList[i]>>j)&1, bk);
        LweSample* temp = new_gate_bootstrapping_ciphertext_array(16,bk->params);
        if(randMulList[i] != 1){
          // multiply(temp, cipherArray[i], constant, 8, bk);
          wallace_multiplier(temp, cipherArray[i], constant, 8, bk);
        }
        else{
            for(int j=0; j < 8; j++)
              bootsCOPY(&temp[j],&cipherArray[i][j], bk);
            for(int j=8; j < 16; j++)
              bootsCONSTANT(&temp[j], 0, bk);
        }
        tempMul.push_back(temp);
    }
    std::cout<< "---Mul finished"<<std::endl;
    std::vector<int> randAddList = GenerateAddList(0, 127,fileNUM,ifList);

    for(int i =0; i < fileNUM; i++){
      for(int j =0; j < 16; j++){
        bootsCONSTANT(&constant[j], (randAddList[i]>>j)&1, bk);
      } 
      LweSample* temp= new_gate_bootstrapping_ciphertext_array(16, bk->params);
      if(randAddList[i] != 0){
        Oracle::full_adder_MUX(temp, tempMul[i], constant, 16, bk);
      }
      else{
        for(int j=0; j < 8; j++)
          bootsCOPY(&temp[j],&cipherArray[i][j], bk);
        for(int j=8; j < 16; j++)
          bootsCONSTANT(&temp[j], 0, bk);
        }
      tempAdd.push_back(temp);
    }
    save_maping_graph(randAddList, "server_folder/client_X_randAddList", fileNUM);
	  save_maping_graph(randMulList, "server_folder/client_X_randMulList", fileNUM);
    std::cout<< "---Add finished"<<std::endl;
    return tempAdd;
};

bool run(CTcpServer TcpServer, int cfd){
    Oracle oracle;
    int recv_data[20];
    std::cout<<"Step1: Initalization"<<std::endl;
    if (TcpServer.RecvFile("server_folder/cloud.key", cfd) == false) {
        perror("Recv key fail");
    }
    std::cout<<"---Recv public key"<< std::endl;
    if (TcpServer.RecvFile("server_folder/enc_credential.json", cfd) == false) {
        perror("Recv credential fail");
    }

    //根据enc_credential.json，按顺序接收属性对应密文并保存
    std::ifstream jsonstream("server_folder/enc_credential.json");
    nlohmann::json credential; 
    jsonstream >> credential;
    nlohmann::json information;
    information = credential["CredentialInformation"];
    std::string signature_base64 = credential["Signature"];
    int* cipherLength = new int[information.size()];
    int index= 0;
    for (auto item : information.items())
    {
        char tmp[30];
        std::string name = item.key();
        int value = information.at(item.key());
        cipherLength[index++] = value;
        std::sprintf(tmp,"./server_folder/%s", item.key().c_str());
        if (TcpServer.RecvFile(tmp, cfd) == false) {
            perror("Recv key fail");
        }
    }
    std::cout<<"---Recv encrypted certificate"<< std::endl;

    FILE* cloud_key = fopen("server_folder/cloud.key","rb");
    TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);

    //把属性名加密并与属性值合并，记录其中消息总数，生成的isCipher记录其中消息为属性值的index
    std::vector<LweSample*> cipherArray;
    std::vector<int> isCipher;

    int fileNUM = 0;
    const TFheGateBootstrappingParameterSet* params = bk->params;
    for (auto item : information.items()){
      int nameLength = item.key().length();
      int valueLength = information.at(item.key());
      fileNUM = fileNUM + nameLength + valueLength;
      for (int i = 0; i < nameLength; i++){ 
        LweSample* ciphertext = new_gate_bootstrapping_ciphertext_array(8, params);
        for (int j=0; j<8; j++){
          // std::cout<<((item.key().c_str()[i]>>j)&1)<<std::endl;
          bootsCONSTANT(&ciphertext[j], (item.key().c_str()[i]>>j)&1, bk);
        }
        cipherArray.push_back(ciphertext);
      }
      char tmp[30];
      std::sprintf(tmp,"./server_folder/%s", item.key().c_str());
      FILE* cloud_data = fopen(tmp,"rb");
      for (int i = 0; i < valueLength; i++){
        LweSample* ciphertext = new_gate_bootstrapping_ciphertext_array(8, params);
        for (int j=0; j<8; j++){
          import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext[j], params);
        }
        isCipher.push_back(fileNUM - valueLength + i - 1);
        cipherArray.push_back(ciphertext);
      } 
      fclose(cloud_data);
    }


    //对数据进行混淆
    std::cout<<"Step2: Begin obfuscation"<<std::endl;
    int obfuscatedNum = 1;
    clock_t start, finish;
    double  duration;
    start = clock();
    std::vector<LweSample*> tempAdd = oracle.obfuscateData(fileNUM, isCipher, obfuscatedNum,cipherArray,bk);
    finish = clock();
    duration = (double)(finish - start) / CLOCKS_PER_SEC;    
    std::cout<<"---obfuscation"<< duration<<" seconds"<<std::endl;
    FILE* confused_data = fopen("server_folder/confused_data","wb");
    for(int i = 0;i < tempAdd.size(); i++){
        for (int j=0; j<16; j++) 
            export_gate_bootstrapping_ciphertext_toFile(confused_data, &tempAdd[i][j], params);
    }
    fclose(confused_data);

    //保存混淆值并发给client端
    std::cout<<"---Send obfuscated data back to client"<<std::endl;
    if (TcpServer.SendFile("server_folder/confused_data", cfd) == false) {
        perror("send fail");
    }
    std::cout<<"Step3: Boolean circuit running"<<std::endl;
    //布尔电路配置
    //e_role为该端角色，secparam为安全参数这里不使能，nvals门电路同时操作数个数，nthread为使用线程
    //port为本端开放端口号
	  e_role role = SERVER;
    uint32_t bitlen = 32, nvals = 1, secparam = 128, nthreads = 1;
    uint16_t port = 7766;
    std::string address = "127.0.0.1";
    e_mt_gen_alg mt_alg = MT_OT;

    e_sharing sharing = S_BOOL;
    seclvl seclvl = get_sec_lvl(secparam);
    OracleOnlineProtocol run_protocol;
    bool success = run_protocol.runProtocolCircuit(signature_base64, fileNUM, role, address, port, seclvl, nvals, nthreads, mt_alg, sharing);

    //与区块链后端通信并上链
    std::cout<<"Step4: On-chaining"<<std::endl;
    std::cout<<"---Connect blockchain backend"<<std::endl;
    int sclient = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in serAddr;
    serAddr.sin_family = AF_INET;
    serAddr.sin_port = htons(8899);
    serAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (connect(sclient, (sockaddr *)&serAddr, sizeof(serAddr)) != 0)
    {
        printf("---Connect java error!\n");
        close(sclient);
        return 0;
    }
    std::string returncode ="";
    if(success){
      printf("---Verify success\n");
      returncode = "success";
    }
    else{
      printf("---Verify fail\n");
      returncode = "fail";
    }
    send(sclient, returncode.c_str(), returncode.length(), 0);
    close(sclient);
    return success;  
}
