#ifndef __ORACLE_CIRCUIT_H_
#define __ORACLE_CIRCUIT_H_

#include "abycore/circuit/circuit.h"
#include "abycore/aby/abyparty.h"
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <cassert>

class BooleanCircuit;

#define ABY_SHA1_INPUT_BITS 512
#define ABY_SHA1_INPUT_BYTES ABY_SHA1_INPUT_BITS/8
#define ABY_SHA256_INPUT_BITS 512
#define ABY_SHA256_INPUT_BYTES ABY_SHA256_INPUT_BITS/8

#define ABY_SHA1_OUTPUT_BITS 160
#define ABY_SHA1_OUTPUT_BYTES ABY_SHA1_OUTPUT_BITS/8
#define ABY_SHA256_OUTPUT_BITS 256
#define ABY_SHA256_OUTPUT_BYTES ABY_SHA256_OUTPUT_BITS/8

#define SHA1CircularShift(bits,word) \
                ((((word) << (bits)) & 0xFFFFFFFF) | \
                ((word) >> (32-(bits))))

const uint32_t ABY_SHA1_H0 = 0x67452301;
const uint32_t ABY_SHA1_H1 = 0xEFCDAB89;
const uint32_t ABY_SHA1_H2 = 0x98BADCFE;
const uint32_t ABY_SHA1_H3 = 0x10325476;
const uint32_t ABY_SHA1_H4 = 0xC3D2E1F0;

const uint32_t ABY_SHA1_K0 = 0x5A827999;
const uint32_t ABY_SHA1_K1 = 0x6ED9EBA1;
const uint32_t ABY_SHA1_K2 = 0x8F1BBCDC;
const uint32_t ABY_SHA1_K3 = 0xCA62C1D6;

const uint32_t ABY_SHA256_H0 =  0x6a09e667;
const uint32_t ABY_SHA256_H1 =  0xbb67ae85;
const uint32_t ABY_SHA256_H2 =  0x3c6ef372;
const uint32_t ABY_SHA256_H3 =  0xa54ff53a;
const uint32_t ABY_SHA256_H4 =  0x510e527f;
const uint32_t ABY_SHA256_H5 =  0x9b05688c;
const uint32_t ABY_SHA256_H6 =  0x1f83d9ab;
const uint32_t ABY_SHA256_H7 =  0x5be0cd19;

 const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

class OracleOnlineProtocol
{
    public:
        uint16_t* msgArray;
        bool runProtocolCircuit(std::string signature_base64,uint32_t bufSize,  e_role role, const std::string& address, uint16_t port, seclvl seclvl, uint32_t nvals, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing);
        share* BuildInverseRandomCircuit(share* msg, share* divRand, share* subRand, uint32_t fileNUM, uint32_t nvals, BooleanCircuit* circ);
        share* BuildDivCircuit(share* dividend, share* divisor, uint32_t nvals, BooleanCircuit* circ);

        share* BuildSHA1Circuit(share* s_msgS, uint8_t* msg, uint8_t* plain_out, uint32_t nvals, BooleanCircuit* circ);
        share* BuildSHA256Circuit(share* s_msgInput, uint32_t nvals, uint32_t bufSize, uint64_t msgSize, BooleanCircuit* circ);
        void verify_SHA1_hash(uint8_t* msg, uint32_t msgbytes, uint32_t nvals, uint8_t* hash);
        void verify_SHA256_hash(uint8_t* msg, uint32_t msgbytes, uint32_t nvals, uint8_t* hash);

    private:
        share* process_block(share* s_msg, uint8_t* msg, uint8_t* tmp_int_out, share** s_h, uint32_t* h, uint32_t nvals, BooleanCircuit* circ);
        share* process_block(share* s_msg, share** s_h, uint32_t nvals, BooleanCircuit* circ);

        void init_AH(share** s_h, uint32_t* h, uint32_t nvals, BooleanCircuit* circ);
        void init_variables(share** s_h, uint32_t* h, uint32_t nvals, BooleanCircuit* circ);
        void init_variables(share** s_h, uint32_t nvals, BooleanCircuit* circ);
        void break_message_to_chunks(share** s_w, share* s_msg, uint32_t* w, uint8_t* msg, BooleanCircuit* circ);
        void break_message_to_chunks(share** s_w, share* s_msg, BooleanCircuit* circ);
        void expand_ws(share** s_w, uint32_t* w, BooleanCircuit* circ);
        void expand_ws(share** s_w, BooleanCircuit* circ);
        share* sigma0(share* s_a, BooleanCircuit* circ);
        share* ma(share* s_a, share* s_b, share* s_c, BooleanCircuit* circ);
        share* sigma1(share* s_e, BooleanCircuit* circ);
        share* ch(share* s_e, share* s_f, share* s_g, BooleanCircuit* circ);
        void sha256_main_loop(share** s_h, share** s_w, uint32_t nvals, BooleanCircuit* circ);
        void sha1_main_loop(share** s_h, share** s_w, uint32_t* h, uint32_t* w, uint32_t nvals, BooleanCircuit* circ);
};


#endif /* __ORECLE_CIRCUIT_H_ */
