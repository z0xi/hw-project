# hw-project

依赖安装
sudo apt-get install -y libgmp-dev libssl-dev libboost-all-dev 

sudo apt-get install -y build-essential cmake cmake-curses-gui

ABY：
主目录下shell运行
git clone https://github.com/encryptogroup/ABY.git
cd ABY/
mkdir build && cd build
cmake ..
make
sudo make install

tfhe：
主目录下shell运行
git clone --recurse-submodules --branch=master https://github.com/tfhe/tfhe.git
cd tfhe
mkdir build
cd build
ccmake ../src
make
sudo make install
TFHE_PREFIX=/usr/local
export C_INCLUDE_PATH=$C_INCLUDE_PATH:$TFHE_PREFIX/include
export CPLUS_INCLUDE_PATH=$CPLUS_INCLUDE_PATH:$TFHE_PREFIX/include
export LIBRARY_PATH=$LIBRARY_PATH:$TFHE_PREFIX/lib
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$TFHE_PREFIX/lib

openssl：
kali应该自带？如果发现openssl的问题安装下openssl环境
使用ssh -V查看openssl版本

nlohmann json：
git clone https://github.com/nlohmann/json.git
cd json-develop
mkdir build
cmake ..
make
sudo make install

在user、oracle下输入命令：
ln -s ABY的目录路径

各个目录下运行
cmake .
make

./verifier为微服务
./oracle为微服务
./client一次性程序，与oracle交互
./user一次性服务，与verifier交互

