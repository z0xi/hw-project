#include "abycore/circuit/booleancircuits.h"
#include "abycore/sharing/sharing.h"
#include <ENCRYPTO_utils/cbitvector.h>
#include <cstring>
#include "client_circuit.h"

// ClientOnlineProtocol::ClientOnlineProtocol(void){}

share* 
ClientOnlineProtocol::BuildDivCircuit(share* dividend, share* divisor, uint32_t nvals, BooleanCircuit* circ) {

	uint32_t zero = 0;
	uint32_t one = 1;
	share* s_zero = circ->PutCONSGate(zero, 16);
	share* s_one = circ->PutCONSGate(one, 16);
	share* s_quotient = circ->PutCONSGate( zero, 16);
	share* s_remainder = circ->PutCONSGate(zero, 16);
	for(uint32_t j = 0; j < 15; j++) {
		s_remainder->set_wire_id(j, dividend->get_wire_id(j));
	}
	share* s_divisor = circ->PutCONSGate(zero, 16);
	for(uint32_t j = 15; j > 7; j--) {
			s_divisor->set_wire_id(j, divisor->get_wire_id(j-8));
	}
	int cnt = 9;

	do
    {
		share* s_temp = circ->PutSUBGate(s_remainder, s_divisor);
		// circ->PutPrintValueGate(s_temp , "temp s_temp");
		share* s_flag = circ->PutMUXGate(s_one, s_zero, s_temp->get_wire_ids_as_share(15));
		s_remainder = circ->PutMUXGate(s_remainder, s_temp, s_flag);
		// circ->PutPrintValueGate(s_remainder , "temp after flag s_remainder");
		share* lastbit = circ->PutMUXGate(s_zero->get_wire_ids_as_share(0), s_one->get_wire_ids_as_share(0), s_flag->get_wire_ids_as_share(0));
    	// circ->PutPrintValueGate(lastbit , "temp lastbit");
		// circ->PutPrintValueGate(s_quotient , "temp 1 s_quotient");
		s_quotient = circ->PutLeftShifterGate(s_quotient, one);
		// circ->PutPrintValueGate(s_quotient , "temp 2 s_quotient");
		s_quotient->set_wire_id(0, lastbit->get_wire_id(0));
		// circ->PutPrintValueGate(s_quotient , "temp 3 s_quotient");
		s_divisor = circ->PutBarrelRightShifterGate(s_divisor, s_one);
		s_divisor->set_wire_id(15, s_zero->get_wire_id(0));
		// circ->PutPrintValueGate(s_quotient , "temp s_quotient");
		cnt --;
    }while(cnt!=0);
	// circ->PutPrintValueGate(s_quotient , "final s_quotient");
	share* flag = circ->PutEQGate(s_remainder, s_zero);
	// circ->PutPrintValueGate(flag , "flag");
	// circ->PutAssertGate(flag, one, 16);
	return s_quotient;
}

share* 
ClientOnlineProtocol::BuildInverseRandomCircuit(share* msg, share* divRand, share* subRand, uint32_t bufSize, uint32_t nvals, BooleanCircuit* circ){
	uint32_t zero = 0;
	uint32_t one = 0;
	uint32_t bitlen_8 = 8;
	share* out = new boolshare(bitlen_8 * bufSize, circ);
	int subIndex = 0;
	int msgIndex = 0;
	int divIndex = 0;
	int outIndex = 0;
	for(int i =0; i < bufSize; i++){
		share* s_zero= circ->PutCONSGate(zero, 16);
		share* s_one= circ->PutCONSGate(one, 16);
		share* s_sub_temp = circ->PutCONSGate(zero, 16);
		share* s_div_temp = circ->PutCONSGate(zero, 16);
		share* s_msg_temp = circ->PutCONSGate(zero, 16);
		for(uint32_t j = 0; j < 8; j++) {
			s_sub_temp->set_wire_id(j, subRand->get_wire_id(subIndex++));
			s_div_temp->set_wire_id(j, divRand->get_wire_id(divIndex++));
		}
		for(uint32_t j = 0; j < 16; j++) {
			s_msg_temp->set_wire_id(j, msg->get_wire_id(msgIndex++));
		}
		// circ->PutPrintValueGate(s_msg_temp, "sub_before");
		s_msg_temp = circ->PutSUBGate(s_msg_temp, s_sub_temp);
		// circ->PutPrintValueGate(s_msg_temp, "sub_after");
		share* s_quotient = BuildDivCircuit(s_msg_temp, s_div_temp, nvals, circ);
		for(uint32_t j = 0; j < 8; j++) {
			out->set_wire_id(outIndex++, s_quotient->get_wire_id(j));
		}
	}
	return out;
};



bool 
ClientOnlineProtocol::runProtocolCircuit(std::vector<uint16_t> msg, uint32_t bufSize, e_role role, const std::string& address, uint16_t port, seclvl seclvl, uint32_t nvals, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing) {
	uint32_t bitlen_8 = 8;
	uint32_t bitlen_16 = 16;
	uint64_t msgSize = bufSize;
	uint32_t divbits_per_party = 8;
	uint32_t divbytes_per_party = bits_in_bytes(divbits_per_party);
	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen_16, nthreads, mt_alg);
	std::vector<Sharing*>& sharings = party->GetSharings();
	Circuit* temp_circ = sharings[sharing]->GetCircuitBuildRoutine();
	BooleanCircuit* circ = (BooleanCircuit*) temp_circ;

	uint16_t msgArray[bufSize];
	for(int j = 0;j < bufSize;j++){
       msgArray = msg[j];
    }

	// circ->PutSIMDINGate(nvals, msgShare.GetArr(), bitlen_16*bufSize, CLIENT);
	share *s_div_out, *s_msg, *s_divRand, *s_subRand;
	s_msg = circ->PutSIMDINGate(nvals, msgArray, bitlen_16*bufSize, CLIENT);
	s_subRand = circ->PutDummyINGate(bitlen_8*bufSize);
	s_divRand = circ->PutDummyINGate(bitlen_8*bufSize);

	share* s_quotient = BuildInverseRandomCircuit(s_msg, s_divRand, s_subRand, bufSize, nvals, circ);
	share* s_hash_out = BuildSHA256Circuit(s_quotient, nvals, bufSize, msgSize, (BooleanCircuit*) circ);

	s_hash_out = circ->PutOUTGate(s_hash_out, ALL);

	party->ExecCircuit();

	CBitVector verify,out;
	verify.Create(ABY_SHA256_OUTPUT_BITS * nvals);
	out.AttachBuf(s_hash_out->get_clear_value_ptr(), (uint64_t) ABY_SHA256_OUTPUT_BITS * nvals);

	for (uint32_t i = 0; i < nvals; i++) {
		std::cout << "(" << i << ") Circ:\t";
		out.PrintHex(i * ABY_SHA256_OUTPUT_BYTES, (i + 1) * ABY_SHA256_OUTPUT_BYTES);
	}
	delete party;
	return 1;
}


share* 
ClientOnlineProtocol::BuildSHA256Circuit(share* s_msgInput, uint32_t nvals, uint32_t bufSize, uint64_t msgSize, BooleanCircuit* circ) {

	uint64_t zero = 0;
	uint64_t one = 1;
	share* s_zero = circ->PutSIMDCONSGate(nvals, zero, 1);
	share* s_one = circ->PutSIMDCONSGate(nvals, one, 1);
	int lastBlockLen = msgSize - (msgSize / 64) * 64;
	int outputBytesLen;
	int round;
	if(lastBlockLen < 56){
		outputBytesLen = msgSize + 64 - lastBlockLen;
	}
	else{
		outputBytesLen = msgSize + 64 - lastBlockLen + 64;
	}
	round = outputBytesLen /64;
	share* s_pad_msg = new boolshare(outputBytesLen * 8, circ);
	for(uint32_t i = 0; i < msgSize * 8; i++) {
		s_pad_msg->set_wire_id(i, s_msgInput->get_wire_id(i));
	}
	for(uint32_t i = msgSize * 8; i < outputBytesLen * 8 - 64; i++) {
		if(i == msgSize * 8 + 7 ) {
			s_pad_msg->set_wire_id(i, s_one->get_wire_id(0));
		} else {
			s_pad_msg->set_wire_id(i, s_zero->get_wire_id(0));
		}
	}
	share* s_lastchunk = circ->PutCONSGate(msgSize * 8, 64);
	for(uint32_t i = outputBytesLen * 8 - 64, j = 64; i < outputBytesLen * 8; j-=8) {
		for(uint32_t k = 0; k < 8; k++)
			s_pad_msg->set_wire_id(i++, s_lastchunk->get_wire_id(j - 8 + k));
	}
	//initialize state variables
	share** s_h = (share**) malloc(sizeof(share*) * 8);
	init_variables(s_h, nvals, circ);


	//Copy shared input into one msg
	share* s_out = new boolshare(ABY_SHA256_OUTPUT_BITS, circ);
	share* s_msg = new boolshare(ABY_SHA256_INPUT_BITS, circ);


	for(uint32_t i = 0; i <round ; i++) {
		for(uint32_t j = 0,k = i*512; j < ABY_SHA256_INPUT_BITS;j++,k++) {
			s_msg->set_wire_id(j, s_pad_msg->get_wire_id(k));
		}
		share *out = process_block(s_msg, s_h, nvals, circ);
		if( i == round-1){
			for(int k = 0; k < ABY_SHA256_OUTPUT_BITS; k++) {
				s_out->set_wire_id(k, out->get_wire_id(k));
			}
		}
	}
	free(s_h);
	return s_out;
}

/* Steps are taken from the wikipedia article on SHA1 */
share* 
ClientOnlineProtocol::BuildSHA1Circuit(share* s_msgInput, uint8_t* msgInput, uint8_t* plain_out, uint32_t nvals, BooleanCircuit* circ) {

	uint32_t party_in_bitlen = ABY_SHA1_INPUT_BITS/2;
	uint32_t party_in_bytelen = ABY_SHA1_INPUT_BYTES/2;

	//Copy shared input into one msg
	share* s_msg = new boolshare(ABY_SHA1_INPUT_BITS, circ);
	for(uint32_t i = 0; i < ABY_SHA1_INPUT_BITS; i++) {
		s_msg->set_wire_id(i, s_msgInput->get_wire_id(i));
	}

	//Copy plaintext input into one msg
	uint8_t* tmp_plain_out = (uint8_t*) malloc(ABY_SHA1_OUTPUT_BYTES);
	uint8_t* msg = (uint8_t*) malloc(ABY_SHA1_INPUT_BYTES);
	memcpy(msg, msgInput, ABY_SHA1_INPUT_BYTES);

	//initialize state variables
	share** s_h = (share**) malloc(sizeof(share*) * 5);
	uint32_t* h = (uint32_t*) malloc(sizeof(uint32_t) * 5);
	init_variables(s_h, h, nvals, circ);

	/*
	 * Process this message block
	 */
	share* out = process_block(s_msg, msg, tmp_plain_out, s_h, h, nvals, circ);

	/*
	 * Do the final SHA1 Result computation.
	 * TODO: The remaining block should be padded and processed here. However, since the
	 * input bit length is fixed to 512 bit, the padding is constant.
	 */
	uint64_t zero = 0;
	uint64_t one = 1;
	share* s_zero = circ->PutSIMDCONSGate(nvals, zero, 1);
	share* s_one = circ->PutSIMDCONSGate(nvals, one, 1);
	for(uint32_t i = 0; i < 512; i++) {
		if(i != 7 && i != 497) {
			s_msg->set_wire_id(i, s_zero->get_wire_id(0));
		} else {
			s_msg->set_wire_id(i, s_one->get_wire_id(0));
		}
	}
	for(uint32_t i = 0; i < 64; i++) {
		if(i == 0) {
			msg[0] = 0x80;
		} else if (i == 62) {
			msg[62] = 0x02;
		} else {
			msg[i] = 0;
		}
	}

	out = process_block(s_msg, msg, tmp_plain_out, s_h, h, nvals, circ);

	memcpy(plain_out, tmp_plain_out, ABY_SHA1_OUTPUT_BYTES);

	free(s_h);
	free(h);
	return out;
}

/*
 * Initialize variables
 * h0 = 0x67452301
 * h1 = 0xEFCDAB89
 * h2 = 0x98BADCFE
 * h3 = 0x10325476
 * h4 = 0xC3D2E1F0
 */

void 
ClientOnlineProtocol::init_variables(share** s_h, uint32_t* h, uint32_t nvals, BooleanCircuit* circ) {
	s_h[0] = circ->PutSIMDCONSGate(nvals, ABY_SHA1_H0, 32);
	s_h[1] = circ->PutSIMDCONSGate(nvals, ABY_SHA1_H1, 32);
	s_h[2] = circ->PutSIMDCONSGate(nvals, ABY_SHA1_H2, 32);
	s_h[3] = circ->PutSIMDCONSGate(nvals, ABY_SHA1_H3, 32);
	s_h[4] = circ->PutSIMDCONSGate(nvals, ABY_SHA1_H4, 32);

	h[0] = ABY_SHA1_H0;
	h[1] = ABY_SHA1_H1;
	h[2] = ABY_SHA1_H2;
	h[3] = ABY_SHA1_H3;
	h[4] = ABY_SHA1_H4;
}

void 
ClientOnlineProtocol::init_variables(share** s_h, uint32_t nvals, BooleanCircuit* circ) {
	s_h[0] = circ->PutSIMDCONSGate(nvals, ABY_SHA256_H0, 32);
	s_h[1] = circ->PutSIMDCONSGate(nvals, ABY_SHA256_H1, 32);
	s_h[2] = circ->PutSIMDCONSGate(nvals, ABY_SHA256_H2, 32);
	s_h[3] = circ->PutSIMDCONSGate(nvals, ABY_SHA256_H3, 32);
	s_h[4] = circ->PutSIMDCONSGate(nvals, ABY_SHA256_H4, 32);
	s_h[5] = circ->PutSIMDCONSGate(nvals, ABY_SHA256_H5, 32);
	s_h[6] = circ->PutSIMDCONSGate(nvals, ABY_SHA256_H6, 32);
	s_h[7] = circ->PutSIMDCONSGate(nvals, ABY_SHA256_H7, 32);
}

void 
ClientOnlineProtocol::init_AH(share** s_h, uint32_t* h, uint32_t nvals, BooleanCircuit* circ) {
	s_h[0] = circ->PutSIMDCONSGate(nvals, h[0], 32);
	s_h[1] = circ->PutSIMDCONSGate(nvals, h[1], 32);
	s_h[2] = circ->PutSIMDCONSGate(nvals, h[2], 32);
	s_h[3] = circ->PutSIMDCONSGate(nvals, h[3], 32);
	s_h[4] = circ->PutSIMDCONSGate(nvals, h[4], 32);
	s_h[5] = circ->PutSIMDCONSGate(nvals, h[5], 32);
	s_h[6] = circ->PutSIMDCONSGate(nvals, h[6], 32);
	s_h[7] = circ->PutSIMDCONSGate(nvals, h[7], 32);
}

share* 
ClientOnlineProtocol::process_block(share* s_msg, share** s_h, uint32_t nvals, BooleanCircuit* circ) {

	share* out = new boolshare(ABY_SHA256_OUTPUT_BITS, circ);
	share** s_w = (share**) malloc(sizeof(share*) * 64);


	//break message into 512-bit chunks
	//for each chunk
	//    break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
	break_message_to_chunks(s_w, s_msg, circ);

    //for i from 16 to 79
     //   w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1
	expand_ws(s_w, circ);

	//Main Loop; result is written into s_h
	sha256_main_loop(s_h, s_w, nvals, circ);

	for(uint32_t i = 0, wid; i < 8; i++) {
		for(uint32_t j = 0; j < 32; j++) {
			if(j < 8) {
				wid = 24;
			} else if (j < 16) {
				wid = 16;
			} else if(j < 24) {
				wid = 8;
			} else {
				wid = 0;
			}
			out->set_wire_id(i*32+j, s_h[i]->get_wire_id(wid + (j%8)));
		}
	}

	free(s_w);

	return out;
}

share* 
ClientOnlineProtocol::process_block(share* s_msg, uint8_t* msg, uint8_t* plain_out, share** s_h, uint32_t* h, uint32_t nvals, BooleanCircuit* circ) {
	//share* out = new share(1, circ);
	share* out = new boolshare(ABY_SHA1_OUTPUT_BITS, circ);
	share** s_w = (share**) malloc(sizeof(share*) * 80);
	uint32_t* w = (uint32_t*) malloc(sizeof(uint32_t) * 80);


	//break message into 512-bit chunks
	//for each chunk
	//    break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
	break_message_to_chunks(s_w, s_msg, w, msg, circ);

    //for i from 16 to 79
     //   w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1
	expand_ws(s_w, w, circ);

	//Main Loop; result is written into s_h
	sha1_main_loop(s_h, s_w, h, w, nvals, circ);

	for(uint32_t i = 0, wid; i < 5; i++) {
		for(uint32_t j = 0; j < 32; j++) {
			if(j < 8) {
				wid = 24;
			} else if (j < 16) {
				wid = 16;
			} else if(j < 24) {
				wid = 8;
			} else {
				wid = 0;
			}
			out->set_wire_id(i*32+j, s_h[i]->get_wire_id(wid + (j%8)));
		}
	}

	for(uint32_t i = 0; i < 5; i++) {
		plain_out[i*4] = (h[i]>>24)&0xFF;
		plain_out[i*4+1] = (h[i]>>16)&0xFF;
		plain_out[i*4+2] = (h[i]>>8)&0xFF;
		plain_out[i*4+3] = (h[i])&0xFF;
	}
	free(s_w);
	free(w);

	return out;
}


void 
ClientOnlineProtocol::break_message_to_chunks(share** s_w, share* s_msg, BooleanCircuit* circ) {
	for(uint32_t i = 0; i < 16; i++) {
		s_w[i] = new boolshare(32, circ);
	}
	//iterate over message bytes
	uint32_t wid;
	for(uint32_t i = 0; i < 16; i++) {
		//iterate over bits
		for(uint32_t j = 0; j < 32; j++) {
			if(j < 8) {
				wid = 24;
			} else if (j < 16) {
				wid = 16;
			} else if(j < 24) {
				wid = 8;
			} else {
				wid = 0;
			}
			s_w[i]->set_wire_id((j%8)+wid, s_msg->get_wire_id(i*32+ j));
		}
	}
}

//break a 512 bit input message into 16 32-bit words in bit endian
void 
ClientOnlineProtocol::break_message_to_chunks(share** s_w, share* s_msg, uint32_t* w, uint8_t* msg, BooleanCircuit* circ) {
	for(uint32_t i = 0; i < 16; i++) {
		s_w[i] = new boolshare(32, circ);
	}
	//iterate over message bytes
	uint32_t wid;
	for(uint32_t i = 0; i < 16; i++) {
		//iterate over bits
		for(uint32_t j = 0; j < 32; j++) {
			if(j < 8) {
				wid = 24;
			} else if (j < 16) {
				wid = 16;
			} else if(j < 24) {
				wid = 8;
			} else {
				wid = 0;
			}
			s_w[i]->set_wire_id((j%8)+wid, s_msg->get_wire_id(i*32+ j));
		}
		w[i] = msg[i*4] << 24;
		w[i] |= (msg[i*4+1] << 16);
		w[i] |= (msg[i*4+2] << 8);
		w[i] |= msg[i*4+3];

	}
}

share* rotateRightShift(share* s, int length, BooleanCircuit* circ) {
	share* out= new boolshare(32, circ);
	for(uint32_t j = 0; j < 32; j++) {
		out->set_wire_id(j, s->get_wire_id((j + length)%32));
	}
	return out;
}

share* rightShift(share* s, int length, BooleanCircuit* circ) {
	share* out= new boolshare(32, circ);
	uint32_t zero = 0;
	share* s_zero = circ->PutCONSGate(zero, 1);
	for(uint32_t j = 0; j < 32 - length; j++) {
		out->set_wire_id(j, s->get_wire_id((j + length)%32));
	}
	for(uint32_t j = 32 - length; j < 32; j++) {
		out->set_wire_id(j, s_zero->get_wire_id(0));
	}
	return out;
}


//for i from 16 to 79
 //   w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1
void 
ClientOnlineProtocol::expand_ws(share** s_w, uint32_t* w, BooleanCircuit* circ) {
	share* s_wtmp;
	for(uint32_t i = 16; i < 80; i++) {
		s_w[i] = new boolshare(32, circ);
		s_wtmp = circ->PutXORGate(s_w[i-3], s_w[i-8]);
		s_wtmp = circ->PutXORGate(s_wtmp, s_w[i-14]);
		s_wtmp = circ->PutXORGate(s_wtmp, s_w[i-16]);
		//leftrotate by 1
		for(uint32_t j = 0; j < 32; j++) {
			s_w[i]->set_wire_id((j+1)%32, s_wtmp->get_wire_id(j));
		}

		w[i] = SHA1CircularShift(1, w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]);
	}
}

//For sha256
void 
ClientOnlineProtocol::expand_ws(share** s_w, BooleanCircuit* circ) {
	for(uint32_t i = 16; i < 64; i++) {
		share *s_wtmp1, *s_wtmp0, *s_wtmp2, *s_wtmp3;
		s_w[i] = new boolshare(32, circ);
		
		s_wtmp2 = rotateRightShift(s_w[i-2], 17, circ);
		s_wtmp3= rotateRightShift(s_w[i-2], 19, circ);
		s_wtmp1 = circ->PutXORGate(s_wtmp3, s_wtmp2);
		s_wtmp2 = rightShift(s_w[i-2], 10, circ);

		s_wtmp1 = circ->PutXORGate(s_wtmp1, s_wtmp2);

		s_wtmp2 = rotateRightShift(s_w[i-15], 7, circ);
		s_wtmp3 = rotateRightShift(s_w[i-15], 18, circ);

		s_wtmp0 = circ->PutXORGate(s_wtmp2, s_wtmp3);
		s_wtmp2 = rightShift(s_w[i-15], 3, circ);

		s_wtmp0 = circ->PutXORGate(s_wtmp0, s_wtmp2);
		s_wtmp1 = circ->PutADDGate(s_wtmp0, s_wtmp1);
		s_wtmp1 = circ->PutADDGate(s_wtmp1 , s_w[i-7]);
		s_wtmp1 = circ->PutADDGate(s_wtmp1 , s_w[i-16]);

		s_w[i]->set_wire_ids(s_wtmp1->get_wires());
	}
}


share* 
ClientOnlineProtocol::ch(share* s_e, share* s_f, share* s_g, BooleanCircuit* circ) {
	share *out, *temp;

	out = circ->PutANDGate(s_e, s_f);
	temp = circ->PutINVGate(s_e); 
	temp = circ->PutANDGate(temp, s_g);
	out = circ->PutXORGate(out, temp);

	return out;
}

share* 
ClientOnlineProtocol::sigma1(share* s_e, BooleanCircuit* circ) {
	share *out, *temp;

	out = rotateRightShift(s_e, 6, circ);
	temp = rotateRightShift(s_e, 11, circ);

	out = circ->PutXORGate(out, temp);
	temp =  rotateRightShift(s_e, 25, circ);
	out = circ->PutXORGate(out, temp);

	return out;
}

share* 
ClientOnlineProtocol::ma(share* s_a, share* s_b, share* s_c, BooleanCircuit* circ) {
	share *out, *temp;

	out = circ->PutANDGate(s_a, s_b);
	temp = circ->PutANDGate(s_a, s_c);
	out = circ->PutXORGate(out, temp);
	temp = circ->PutANDGate(s_b, s_c);
	out = circ->PutXORGate(out, temp);
	
	return out;
}

share* 
ClientOnlineProtocol::sigma0(share* s_a, BooleanCircuit* circ) {
	share *out, *temp;
	
	out =  rotateRightShift(s_a, 2, circ);
	temp =  rotateRightShift(s_a, 13, circ);
	out = circ->PutXORGate(out, temp);
	temp = rotateRightShift(s_a, 22, circ);
	out = circ->PutXORGate(out, temp);

	return out;
}

void 
ClientOnlineProtocol::sha256_main_loop(share** s_hash, share** s_w, uint32_t nvals, BooleanCircuit* circ) {
	/*
	 * Initialize hash value for this chunk:
	 * a = h0; b = h1; c = h2; d = h3; e = h4
	*/
	share *s_a, *s_b, *s_c, *s_d, *s_e, *s_f, *s_g, *s_h;
	s_a = new boolshare(32, circ);
	s_b = new boolshare(32, circ);
	s_c = new boolshare(32, circ);
	s_d = new boolshare(32, circ);
	s_e = new boolshare(32, circ);
	s_f = new boolshare(32, circ);
	s_g = new boolshare(32, circ);
	s_h = new boolshare(32, circ);

	s_a->set_wire_ids(s_hash[0]->get_wires());
	s_b->set_wire_ids(s_hash[1]->get_wires());
	s_c->set_wire_ids(s_hash[2]->get_wires());
	s_d->set_wire_ids(s_hash[3]->get_wires());
	s_e->set_wire_ids(s_hash[4]->get_wires());
	s_f->set_wire_ids(s_hash[5]->get_wires());
	s_g->set_wire_ids(s_hash[6]->get_wires());
	s_h->set_wire_ids(s_hash[7]->get_wires());
	/*
	 * Main loop
	 * for i from 0 to 63
	 */
			share *s_k, *s_tmp, *s_tmpA, *s_ch, *s_ma, *s_sigma0, *s_sigma1;

	for(uint32_t i = 0; i < 64; i++) {
		// share *s_k, *s_tmp, *s_tmpA, *s_ch, *s_ma, *s_sigma0, *s_sigma1;
		s_ch = ch(s_e, s_f, s_g, circ);
		s_ma = ma(s_a, s_b, s_c, circ);
		s_sigma0 = sigma0(s_a, circ);
		s_sigma1 = sigma1(s_e, circ);

		s_k = circ->PutSIMDCONSGate(nvals, k[i], 32);
		s_tmp = circ->PutADDGate(s_w[i], s_k);
		s_tmp = circ->PutADDGate(s_tmp, s_h);
		s_tmp = circ->PutADDGate(s_tmp, s_ch);
		s_tmp = circ->PutADDGate(s_tmp, s_sigma1);

		s_tmpA = circ->PutADDGate(s_tmp, s_ma);
		s_tmpA = circ->PutADDGate(s_tmpA, s_sigma0);

		s_tmp = circ->PutADDGate(s_tmp, s_d);


		s_h->set_wire_ids(s_g->get_wires());
		s_g->set_wire_ids(s_f->get_wires());
		s_f->set_wire_ids(s_e->get_wires());
		s_e->set_wire_ids(s_tmp->get_wires());
		s_d->set_wire_ids(s_c->get_wires());
		s_c->set_wire_ids(s_b->get_wires());
		s_b->set_wire_ids(s_a->get_wires());
		s_a->set_wire_ids(s_tmpA->get_wires());

		// circ->PutPrintValueGate(s_a,"s_a:");
		// circ->PutPrintValueGate(s_b,"s_b:");
		// circ->PutPrintValueGate(s_c,"s_c:");
		// circ->PutPrintValueGate(s_d,"s_d:");
		// circ->PutPrintValueGate(s_e,"s_e:");
		// circ->PutPrintValueGate(s_f,"s_f:");
		// circ->PutPrintValueGate(s_g,"s_g:");
		// circ->PutPrintValueGate(s_h,"s_h:");
	}
	/*
	 * Set output; Add this chunk's hash to result so far:
	 */
	s_hash[0] = circ->PutADDGate(s_hash[0], s_a);
	s_hash[1] = circ->PutADDGate(s_hash[1], s_b);
	s_hash[2] = circ->PutADDGate(s_hash[2], s_c);
	s_hash[3] = circ->PutADDGate(s_hash[3], s_d);
	s_hash[4] = circ->PutADDGate(s_hash[4], s_e);
	s_hash[5] = circ->PutADDGate(s_hash[5], s_f);
	s_hash[6] = circ->PutADDGate(s_hash[6], s_g);
	s_hash[7] = circ->PutADDGate(s_hash[7], s_h);
}

void 
ClientOnlineProtocol::sha1_main_loop(share** s_h, share** s_w, uint32_t* h, uint32_t* w, uint32_t nvals, BooleanCircuit* circ) {
	/*
	 * Initialize hash value for this chunk:
	 * a = h0; b = h1; c = h2; d = h3; e = h4
	*/
	share *s_a, *s_b, *s_c, *s_d, *s_e;
	s_a = new boolshare(32, circ);
	s_b = new boolshare(32, circ);
	s_c = new boolshare(32, circ);
	s_d = new boolshare(32, circ);
	s_e = new boolshare(32, circ);

	s_a->set_wire_ids(s_h[0]->get_wires());
	s_b->set_wire_ids(s_h[1]->get_wires());
	s_c->set_wire_ids(s_h[2]->get_wires());
	s_d->set_wire_ids(s_h[3]->get_wires());
	s_e->set_wire_ids(s_h[4]->get_wires());

	uint32_t a, b, c, d, e;
	a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4];

	/*
	 * Main loop
	 * for i from 0 to 79
	 */
	share *s_f, *s_k, *s_tmp;
	uint32_t f, k, tmp;
	for(uint32_t i = 0; i < 80; i++) {

		if(i < 20) {
		/*
		 * if 0 ≤ i ≤ 19 then
		 *     f = (b and c) xor ((not b) and d)
		 *     k = 0x5A827999
		 */
			s_f = circ->PutANDGate(s_b, s_c);
			s_tmp = circ->PutINVGate(s_b);
			s_tmp = circ->PutANDGate(s_tmp, s_d);
			s_f = circ->PutXORGate(s_f, s_tmp);
			s_k = circ->PutSIMDCONSGate(nvals, ABY_SHA1_K0, 32);

			f = (b & c) | ((~b) & d);
			k = ABY_SHA1_K0;
		} else if(i < 40) {
		/*
         * else if 20 ≤ i ≤ 39
         * 		f = b xor c xor d
         * 		k = 0x6ED9EBA1
		 */
			s_f = circ->PutXORGate(s_b, s_c);
			s_f = circ->PutXORGate(s_f, s_d);
			s_k = circ->PutSIMDCONSGate(nvals, ABY_SHA1_K1, 32);

			f = b ^ c ^ d;
			k = ABY_SHA1_K1;
		} else if(i < 60) {
		/*
         * else if 40 ≤ i ≤ 59
         * 		f = (b and c) xor (b and d) xor (c and d)
         *  	k = 0x8F1BBCDC
		 */
			s_f = circ->PutANDGate(s_b, s_c);
			s_tmp = circ->PutANDGate(s_b, s_d);
			s_f = circ->PutXORGate(s_f, s_tmp);
			s_tmp = circ->PutANDGate(s_c, s_d);
			s_f = circ->PutXORGate(s_f, s_tmp);
			s_k = circ->PutSIMDCONSGate(nvals, ABY_SHA1_K2, 32);

			f = (b & c) | (b & d) | (c & d);
			k = ABY_SHA1_K2;
		} else if(i < 80) {
			/*
      	  	 * else if 60 ≤ i ≤ 79
             * 		f = b xor c xor d
             * 		k = 0xCA62C1D6
			 */
			s_f = circ->PutXORGate(s_b, s_c);
			s_f = circ->PutXORGate(s_f, s_d);
			s_k = circ->PutSIMDCONSGate(nvals, ABY_SHA1_K3, 32);

			f = (b ^ c ^ d);
			k = ABY_SHA1_K3;
		}
		/*
		 * temp = (a leftrotate 5) + f + e + k + w[i]
		 */
		s_tmp = new boolshare(32, circ);
		for(uint32_t j = 0; j <32; j++) {
			s_tmp->set_wire_id((j+5)%32, s_a->get_wire_id(j));
		}
		s_tmp = circ->PutADDGate(s_tmp, s_f);
		s_tmp = circ->PutADDGate(s_tmp, s_e);
		s_tmp = circ->PutADDGate(s_tmp, s_k);
		s_tmp = circ->PutADDGate(s_tmp, s_w[i]);

		tmp = SHA1CircularShift(5, a);
		tmp = (tmp + f) & 0xFFFFFFFF;
		tmp = (tmp + e) & 0xFFFFFFFF;
		tmp = (tmp + k) & 0xFFFFFFFF;
		tmp = (tmp + w[i]) & 0xFFFFFFFF;

		// e = d
		s_e->set_wire_ids(s_d->get_wires());
		e = d;
        // d = c
		s_d->set_wire_ids(s_c->get_wires());
		d = c;
		// c = b leftrotate 30
		for(uint32_t j = 0; j <32; j++) {
			s_c->set_wire_id((j+30)%32, s_b->get_wire_id(j));
		}
		c = SHA1CircularShift(30, b);
		// b = a
		s_b->set_wire_ids(s_a->get_wires());
		b = a;
		// a = temp
		s_a->set_wire_ids(s_tmp->get_wires());
		a = tmp;

	}


	/*
	 * Set output; Add this chunk's hash to result so far:
	 * h0 = h0 + a; h1 = h1 + b; h2 = h2 + c; h3 = h3 + d; h4 = h4 + e
	 */
	s_h[0] = circ->PutADDGate(s_h[0], s_a);
	s_h[1] = circ->PutADDGate(s_h[1], s_b);
	s_h[2] = circ->PutADDGate(s_h[2], s_c);
	s_h[3] = circ->PutADDGate(s_h[3], s_d);
	s_h[4] = circ->PutADDGate(s_h[4], s_e);

	h[0] = (h[0] + a) & 0xFFFFFFFF;
	h[1] = (h[1] + b) & 0xFFFFFFFF;
	h[2] = (h[2] + c) & 0xFFFFFFFF;
	h[3] = (h[3] + d) & 0xFFFFFFFF;
	h[4] = (h[4] + e) & 0xFFFFFFFF;
}

void 
ClientOnlineProtocol::verify_SHA1_hash(uint8_t* msg, uint32_t msgbytes, uint32_t nvals, uint8_t* hash) {

	uint8_t* input_buf = (uint8_t*) calloc(ABY_SHA1_INPUT_BYTES, sizeof(uint8_t));
	crypto* crypt_tmp = new crypto(80, (uint8_t*) const_seed);

	for(uint32_t i = 0; i < nvals; i++) {
		memcpy(input_buf, msg, msgbytes);
		crypt_tmp->hash(hash+i*ABY_SHA1_OUTPUT_BYTES, ABY_SHA1_OUTPUT_BYTES, input_buf, ABY_SHA1_INPUT_BYTES);
	}
	delete crypt_tmp;
}

void 
ClientOnlineProtocol::verify_SHA256_hash(uint8_t* msg, uint32_t msgbytes, uint32_t nvals, uint8_t* hash) {

	uint8_t* input_buf = (uint8_t*) calloc(ABY_SHA256_INPUT_BYTES, sizeof(uint8_t));
	crypto* crypt_tmp = new crypto(90, (uint8_t*) const_seed);

	for(uint32_t i = 0; i < nvals; i++) {
		memcpy(input_buf, msg, msgbytes);
		crypt_tmp->hash(hash+i*ABY_SHA256_OUTPUT_BYTES, ABY_SHA256_OUTPUT_BYTES, input_buf, ABY_SHA256_INPUT_BYTES);
	}
	delete crypt_tmp;
}

