#include "verifier.h"

// Verifier::Verifier(){}

void get_maping_graph(uint16_t *g_maping_graph, char *path, int length)
{
	//std::ifstream fp(path);//只读文件 ，也可由下一句替代
	std::fstream fp(path, std::ios::in);//只读文件
	int temp;
	if (!fp.is_open())
	{
		printf("could not load file: %s\n", path);
		return;
	}
 
	for (int i = 0; i < length; i++)
	{
		fp >> temp;
		g_maping_graph[i]= temp;
	}
	// printf("get maping_graph done .\n ");
	fp.close();
}

std::vector<int> 
Verifier::generateRandNumber(int min,int max,int num)
{
    std::vector<int> numbers;
    std::vector<int> diff;
    for(int i = 0;i < max;i++)
    {
      numbers.push_back(i);
    }
    std::random_shuffle(numbers.begin(),numbers.end());

    for(int i = 0 ; i < num ; i++)
    {
      diff.push_back(numbers[i]);
    }
    sort(diff.begin(), diff.end());
    return diff;
}

std::vector<int> 
Verifier::GenerateMulList(int min,int max, int num, std::vector<int> ifList)
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
Verifier::GenerateAddList(int min,int max, int num, std::vector<int> ifList)
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
Verifier::adder(LweSample* result, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
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
Verifier::multiply(LweSample* product, LweSample* a, LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk){
        
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
        Verifier::full_adder_MUX(partial_sum,product,temp_result,2*nb_bits,bk);
        //Change the partial sum to final product//
        for(int j=0;j<2*nb_bits;j++){ 
            bootsCOPY(&product[j],&partial_sum[j],bk);
        }
    }
}


void 
Verifier::threadMultiply(std::vector<LweSample*> &product, std::vector<LweSample*> ciphertext, std::vector<int> mulList, int threadNum, const TFheGateBootstrappingCloudKeySet* bk)
{
  int num = ciphertext.size();
	// std::vector<pthread_t> calThreads(threadNum);
  std::vector<std::thread> my_threads;
  for(int i =0; i < num; i++){
    LweSample* temp = new_gate_bootstrapping_ciphertext_array(16, bk->params);
    product.push_back(temp);
  }
  std::vector<int> noMul;
  std::vector<int> mul;
  for(int i =0; i < num; i++){
    if(mulList[i] == 1)
      noMul.push_back(i);
    else
      mul.push_back(i);
  }

  for (int i = 0; i < noMul.size(); i++){
    for(int k=0; k < 8; k++)
      bootsCOPY(&product[noMul[i]][k],&ciphertext[noMul[i]][k], bk);
    for(int k=8; k < 16; k++)
      bootsCONSTANT(&product[noMul[i]][k], 0, bk);
  }

  for (int i = 0; i < mul.size(); ){
    int j = 0;
    for(; j < threadNum; j++){
        LweSample* constant = new_gate_bootstrapping_ciphertext_array(16, bk->params);
        for(int k =0; k < 16; k++)
          bootsCONSTANT(&constant[k], (mulList[mul[i+j]]>>k)&1, bk);
        // std::thread th(&Verifier::multiply, this, product[mul[i+j]], ciphertext[mul[i+j]], constant, 8, bk);
        // my_threads.push_back(th);
        my_threads.push_back(std::thread(&Verifier::multiply, this, product[mul[i+j]], ciphertext[mul[i+j]], constant, 8, bk));
        // std::cout<<"thread begin "<< my_threads[j].get_id() <<std::endl;
    }
    void *status;
    for(int k = 0; k < threadNum; k++ ) {
      my_threads[k].join();
    }
    my_threads.clear();
    i = i + threadNum;
  }
}


void
Verifier::full_adder_MUX(LweSample *sum, const LweSample *x, const LweSample *y, const int32_t nb_bits,
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
Verifier::wallace_multiplier(LweSample *result,
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
    Verifier::full_adder_MUX(result, a, b, 2*nb_bits, bk);
    // ripple_carry_adder(result, carry, a, b, 2*nb_bits, bk);
  }

}

void compare_bit(LweSample* result, const LweSample* a, const LweSample* b, LweSample* lsb_carry, LweSample* tmp, const TFheGateBootstrappingCloudKeySet* bk) {
    LweSample* temp1=new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* temp2=new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* temp3=new_gate_bootstrapping_ciphertext_array(1,bk->params);
    LweSample* temp4=new_gate_bootstrapping_ciphertext_array(1,bk->params);
    LweSample* temp5=new_gate_bootstrapping_ciphertext_array(1,bk->params);

    bootsXOR(temp1, a, b, bk);  //a xorb
    bootsXOR(result,temp1,lsb_carry,bk);  //a xor b xor ci
    
    bootsNOT(temp4,a,bk);  // complement of a
    bootsAND(temp3,temp4,b,bk); // complement a and b

    bootsNOT(temp5,temp1,bk);  // complement of a XOR b

    bootsAND(temp2,temp5,lsb_carry,bk);// complement of a XOR b AND lasb_carry
  
    bootsOR(tmp,temp2,temp3,bk);       // a&b + ci*(a xor b)
    bootsCOPY(lsb_carry,tmp,bk);
}

void subtract(LweSample* result, LweSample* tmps, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    //run the elementary comparator gate n times//
      
  	for (int i=0; i<nb_bits; i++){
        compare_bit(&result[i], &a[i], &b[i], &tmps[0], &tmps[1], bk);
    }
}

void 
Verifier::threadAdd(std::vector<LweSample*> &product, std::vector<LweSample*> ciphertext, std::vector<int> addList, int threadNum, const TFheGateBootstrappingCloudKeySet* bk)
{
  int num = ciphertext.size();
	// std::vector<pthread_t> calThreads(threadNum);
  std::vector<std::thread*> my_threads;
  for(int i =0; i < num; i++){
    LweSample* temp = new_gate_bootstrapping_ciphertext_array(16, bk->params);
    product.push_back(temp);
  }

  for (int i = 0; i < num; ){
    int j = 0;
    for(; j < threadNum; j++){
        LweSample* constant = new_gate_bootstrapping_ciphertext_array(16, bk->params);
        for(int k =0; k < 16; k++)
          bootsCONSTANT(&constant[k], (addList[i+j]>>k)&1, bk);
          //Can't work. Wait to fix
        // std::thread th(&Verifier::full_adder_MUX, this, product[i+j], ciphertext[i+j], constant, 16, bk);
        // my_threads.push_back(&th);
    }
    void *status;
    for(int k = 0; k < threadNum; k++ ) {
      my_threads[k]->join();
    }
    my_threads.clear();
    i = i + threadNum;
  }
}


void 
Verifier::save_maping_graph(std::vector<int> g_maping_graph, char *path, int length)
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
Verifier::obfuscateData(int fileNUM, int obfuscatedNum, std::vector<LweSample*> cipherArray, TFheGateBootstrappingCloudKeySet* bk)
{
    std::vector<int> ifList = generateRandNumber(0, fileNUM, obfuscatedNum);

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
    // threadMultiply(tempMul, cipherArray, randMulList, 2, bk);
    std::cout<< "Mul finished"<<std::endl;
    std::vector<int> randAddList = GenerateAddList(0, 127,fileNUM,ifList);
  for(int i = 0;i < fileNUM;i++){
  printf("%d ",randAddList[i]);
}
    // threadAdd(tempAdd, tempMul, randAddList, 2, bk);
    for(int i =0; i < fileNUM; i++){
      for(int j =0; j < 16; j++){
        bootsCONSTANT(&constant[j], (randAddList[i]>>j)&1, bk);
      } 
      LweSample* temp= new_gate_bootstrapping_ciphertext_array(16, bk->params);
      if(randAddList[i] != 0){
        Verifier::full_adder_MUX(temp, tempMul[i], constant, 16, bk);
      }
      else{
        for(int j=0; j < 8; j++)
          bootsCOPY(&temp[j],&cipherArray[i][j], bk);
        for(int j=8; j < 16; j++)
          bootsCONSTANT(&temp[j], 0, bk);
        }
      tempAdd.push_back(temp);
    }
    save_maping_graph(randAddList, "verifier_folder/client_X_randAddList", fileNUM);
	  save_maping_graph(randMulList, "verifier_folder/client_X_randMulList", fileNUM);
    std::cout<< "Add finished"<<std::endl;
    return tempAdd;
};

int run(CTcpServer TcpServer, int cfd){  
    Verifier verifier;

    int recv_data[20];
    if (TcpServer.RecvFile("verifier_folder/cloud.key", cfd) == false) {
        perror("Recv key fail");
    }
    std::cout<<"Recv public key finish"<< std::endl;
    if (TcpServer.RecvFile("verifier_folder/to_v_attr.json", cfd) == false) {
        perror("Recv credential fail");
    }
    std::cout<<"Recv attribute finish"<< std::endl;

    //debug
    if (TcpServer.RecvFile("verifier_folder/enc_credential_v.json", cfd) == false) {
        perror("Recv credential fail");
    }

    //Connect java socket
    int sclient = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in serAddr;
    serAddr.sin_family = AF_INET;
    serAddr.sin_port = htons(8888);
    serAddr.sin_addr.s_addr = inet_addr("192.168.95.1");
    if (connect(sclient, (sockaddr *)&serAddr, sizeof(serAddr)) != 0)
    {  //连接失败 
        printf("connect java error !");
        close(sclient);
        return 0;
    }
    char recData[1];
    int ret = recv(sclient, recData, 9, 0);
    if (!strcmp(recData,"FileReady")) {
      std::cout<<"on-chain attribute is OK!"<<std::endl;
    }

    std::ifstream jsonstream0("verifier_folder/to_v_attr.json");
    std::ifstream jsonstream("verifier_folder/enc_credential_v.json");
    nlohmann::json attrs;
    nlohmann::json credential;
    jsonstream0 >> attrs;
    jsonstream >> credential;
    
    int* cipherLength = new int[credential.size()];
    int index= 0;
    //reads the cloud key from file
    FILE* cloud_key = fopen("verifier_folder/cloud.key","rb");
    TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);

    //if necessary, the params are inside the key
    std::vector<LweSample*> cipherArray;
    int fileNUM = 0;
    const TFheGateBootstrappingParameterSet* params = bk->params;

    for (auto item : attrs.items()){
      std::string value_of_attr_plaintext = attrs.at(item.key());
      int valueLength = value_of_attr_plaintext.length();

      std::string enc_attributes_base64 = credential[item.key()];
      std::string enc_attributes_str="";
      int size;
	    char * enc_attributes = Base64Decode(&size, (char *)enc_attributes_base64.c_str(), enc_attributes_base64.length(), 0);
      for(int i =0; i<size;i++){
        enc_attributes_str +=enc_attributes[i];
      }
      std::istringstream encrypted_stream(enc_attributes_str);
      fileNUM = fileNUM + valueLength;
      for (int i = 0; i < valueLength; i++){ 
        LweSample* attr_user = new_gate_bootstrapping_ciphertext_array(8, params);
        LweSample* attr_chain = new_gate_bootstrapping_ciphertext_array(8, params);
        LweSample* temp = new_gate_bootstrapping_ciphertext_array(8, params);
        LweSample* signbit = new_gate_bootstrapping_ciphertext_array(2, params);;
        bootsCONSTANT(&signbit[0], 0, bk);
        for (int j=0; j<8; j++){
          bootsCONSTANT(&attr_user[j], (value_of_attr_plaintext.c_str()[i]>>j)&1, bk);
        }
        for (int j=0; j<8; j++){
          import_gate_bootstrapping_ciphertext_fromStream(encrypted_stream, &attr_chain[j], params);
        }

        subtract(temp, signbit, attr_user, attr_chain, 8, bk);
        cipherArray.push_back(temp);
      }
    }
    int obfuscatedNum = 10;
    std::vector<LweSample*> tempAdd = verifier.obfuscateData(fileNUM, obfuscatedNum,cipherArray,bk);

    FILE* confused_data = fopen("verifier_folder/verifier_confused_data","wb");
    for(int i = 0;i < tempAdd.size(); i++){
        for (int j=0; j<16; j++) 
            export_gate_bootstrapping_ciphertext_toFile(confused_data, &tempAdd[i][j], params);
    }
    fclose(confused_data);

    if (TcpServer.SendFile("verifier_folder/verifier_confused_data", cfd) == false) {
        perror("send fail");
    }
    std::cout<<"Wait for decrypted confused data"<<std::endl;

    if (TcpServer.RecvFile("verifier_folder/decrypted_confused_data", cfd) == false) {
        perror("Recv credential fail");
    }
    uint16_t addList[fileNUM];
    uint16_t mulList[fileNUM];
    uint16_t bufArray[fileNUM];
    memset(addList, 0, fileNUM);
    memset(mulList, 0, fileNUM);
    memset(bufArray, 0, fileNUM);

    get_maping_graph(addList, "verifier_folder/client_X_randAddList", fileNUM);
    get_maping_graph(mulList, "verifier_folder/client_X_randMulList", fileNUM);
    get_maping_graph(bufArray, "verifier_folder/decrypted_confused_data", fileNUM);

    std::cout<<"Recv OK!"<<std::endl;;
    std::string returncode ="success";
  
    for(int i =0; i < fileNUM;i++){
      if((bufArray[i] - addList[i] + mulList[i] -1)/ mulList[i] != 0){
        printf("Attributes verify fail");
        returncode = "fail";
        break;
      }
    }
    send(sclient, returncode.c_str(), returncode.length(), 0);
    std::cout<<"Send JAVA backend OK!"<<std::endl;;
    close(sclient);
    return 1;  
 }  