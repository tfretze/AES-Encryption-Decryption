
AdvancedEncrypt::AdvancedEncrypt()
{}

AdvancedEncrypt::~AdvancedEncrypt()
{}

void AdvancedEncrypt::SubBytes()
{
	for(int i = 0; i < 16; i++)
	{
		state[i] = sbox[state[i].to_ulong()];//loop through each byte in the state and replace the byte with the substitution corresponding with the s-box value
	}
}

void AdvancedEncrypt::InvSubBytes() 
{
	for(int i = 0; i < 16; i++)
	{
		state[i] = invsbox[state[i].to_ulong()]; //loop through each byte in the state and replace the byte with the substitution corresponding with the inv_s-box value
	}
}

void AdvancedEncrypt::ShiftRows()
{
	for(int i = 0; i < 4; i++) //loop through each byte and move byte left by the amount corresponding with the row number
	{
		tmp[i*4] = state[i*4];
		tmp[(i*4) + 1] = state[((((i+1)*4)+1)%16)];
		tmp[(i*4) + 2] = state[((((i+2)*4)+2)%16)];
		tmp[(i*4) + 3] = state[((((i+3)*4)+3)%16)];
	}

	for(int i = 0; i < 16; i++)
	{
		state[i] = tmp[i];
	}
}

void AdvancedEncrypt::InvShiftRows()
{
	for(int i = 0; i < 4; i++)//loop through each byte and move byte right by the amount corresponding with the row number
	{
		tmp[i*4] = state[i*4];
		tmp[((((i+1)*4)+1)%16)] = state[(i*4) + 1];
		tmp[((((i+2)*4)+2)%16)] = state[(i*4) + 2];
		tmp[((((i+3)*4)+3)%16)] = state[(i*4) + 3];
	}

	for(int i = 0; i < 16; i++)
	{
		state[i] = tmp[i];
	}  
}

void AdvancedEncrypt::MixColumns()
{
	for(int i = 0; i < 16; i += 4) 
	{
		tmp[i] = (mul2[state[i].to_ulong()] ^ mul3[state[i + 1].to_ulong()] ^ state[i + 2] ^ state[i + 3]);     // 02.s1 ^ 03.s2 ^ 01.s3 ^ 01.s4
		tmp[i + 1] = (state[i] ^ mul2[state[i + 1].to_ulong()] ^ mul3[state[i + 2].to_ulong()] ^ state[i + 3]); // 01.s1 ^ 02.s2 ^ 03.s3 ^ 01.s4
	    tmp[i + 2] = (state[i] ^ state[i + 1] ^ mul2[state[i + 2].to_ulong()] ^ mul3[state[i + 3].to_ulong()]); // 01.s1 ^ 01.s2 ^ 02.s3 ^ 03.s4
		tmp[i + 3] = (mul3[state[i].to_ulong()] ^ state[i + 1] ^ state[i + 2] ^ mul2[state[i + 3].to_ulong()]); // 03.s1 ^ 01.s2 ^ 01.s3 ^ 02.s4
	}

	for(int i = 0; i < 16; i++)
	{
		state[i] = tmp[i]; //copy temp array to state
	}	

}

void AdvancedEncrypt::InvMixColumns()
{

	for(int i = 0; i < 16; i += 4)                                                                                                                    //repeat 4 times for all 16 bytes
	{	
		tmp[i] = (mul14[state[i].to_ulong()] ^ mul11[state[i + 1].to_ulong()] ^ mul13[state[i + 2].to_ulong()] ^ mul9[state[i + 3].to_ulong()]);      // 14.s1 ^ 11.s2 ^ 13.s3 ^ 9.s4
		tmp[i + 1] = (mul9[state[i].to_ulong()] ^ mul14[state[i + 1].to_ulong()] ^ mul11[state[i + 2].to_ulong()] ^ mul13[state[i + 3].to_ulong()]);  // 09.s1 ^ 14.s2 ^ 11.s3 ^ 13.s4
	    tmp[i + 2] = (mul13[state[i].to_ulong()] ^ mul9[state[i + 1].to_ulong()] ^ mul14[state[i + 2].to_ulong()] ^ mul11[state[i + 3].to_ulong()]);  // 13.s1 ^ 09.s2 ^ 14.s3 ^ 11.s4
		tmp[i + 3] = (mul11[state[i].to_ulong()] ^ mul13[state[i + 1].to_ulong()] ^ mul9[state[i + 2].to_ulong()] ^ mul14[state[i + 3].to_ulong()]);  // 11.s1 ^ 13.s2 ^ 09.s3 ^ 14.s4
	}

	for(int i = 0; i < 16; i++)
	{
		state[i] = tmp[i]; //copy temp array to state
	}	
}

void AdvancedEncrypt::AddRoundKey(bitset<8>* roundKey)
{
	for(int i = 0; i < 16; i++)
	{
		state[i] ^= roundKey[i];  //xor state with the corresponding round key 
	}
}

void AdvancedEncrypt::copyState(int round)
{
	for(int i = 0; i < 16; i++)
	{
		roundState[(round * 16) + i] = state[i];  //copy the state into the round state to be used for avalanche effect calculations
	}
}

void AdvancedEncrypt::AES_Encrypt0(bitset<8>* plaintext, bitset<8>* expandedKey)
{
	//copy plaintext to the state
	for(int i = 0; i < 16; i++)state[i] = plaintext[i];

	AddRoundKey(expandedKey); //perform initial Addroundkey function
	
	for(int i = 0; i < 9; i++)
	{
 		SubBytes();  //perform substitute bytes function
 		ShiftRows(); //perform shift rows function
 		MixColumns();//perform Mix columns function
 		AddRoundKey(expandedKey + (16 * (i + 1))); //each round uses the next expanded key
 		copyState(i); //copy the state for each round for avalanche analysis
	} 

	//final round
    SubBytes();    //perform substitute bytes function
	ShiftRows();    //perform shift rows function
	AddRoundKey(expandedKey + 160);
	copyState(9); //copy the state for each round for avalanche analysis
}


void AdvancedEncrypt::AES_Encrypt1(bitset<8>*  plaintext, bitset<8>* expandedKey)
{
	//copy plaintext to state
	for(int i = 0; i < 16; i++)state[i] = plaintext[i];
	AddRoundKey(expandedKey); //perform initial Addroundkey function
	
	for(int i = 0; i < 9; i++)
	{
 		ShiftRows();
 		MixColumns();
 		AddRoundKey(expandedKey + (16 * (i + 1))); //each round uses the next expanded key
 		copyState(i);
	} 

	//final round
	ShiftRows();
	AddRoundKey(expandedKey + 160);
	copyState(9);
}

void AdvancedEncrypt::AES_Encrypt2(bitset<8>*  plaintext, bitset<8>* expandedKey)
{
	//copy plaintext to state
	for(int i = 0; i < 16; i++)state[i] = plaintext[i];
	AddRoundKey(expandedKey); //perform initial Addroundkey function
	
	for(int i = 0; i < 9; i++)
	{
 		SubBytes();
 		MixColumns();
 		AddRoundKey(expandedKey + (16 * (i + 1))); //each round uses the next expanded key
 		copyState(i);
	} 

	//final round
    SubBytes();
	AddRoundKey(expandedKey + 160);
	copyState(9);
}

void AdvancedEncrypt::AES_Encrypt3(bitset<8>*  plaintext, bitset<8>* expandedKey)
{
	//copy plaintext to state
	for(int i = 0; i < 16; i++)state[i] = plaintext[i];
	AddRoundKey(expandedKey); //perform initial Addroundkey function
	
	for(int i = 0; i < 9; i++)
	{
 		SubBytes();
 		ShiftRows();
 		AddRoundKey(expandedKey + (16 * (i + 1))); //each round uses the next expanded key
 		copyState(i);
	} 

	//final round
    SubBytes();
	ShiftRows();
	AddRoundKey(expandedKey + 160);
	copyState(9);
}

void AdvancedEncrypt::AES_Encrypt4(bitset<8>*  plaintext, bitset<8>* expandedKey)
{
	//copy plaintext to state
	for(int i = 0; i < 16; i++)state[i] = plaintext[i];
	AddRoundKey(expandedKey);   //perform initial Addroundkey function

	for(int i = 0; i < 9; i++) //perform all the functions of AES 9 times
	{
 		SubBytes();
 		ShiftRows();
 		MixColumns();
 		copyState(i); //copy the state at the end of every round
	} 

	//final round remove mix columns
    SubBytes();
	ShiftRows();
	copyState(9);
}

void AdvancedEncrypt::AES_Decrypt(bitset<8>* ciphertext, bitset<8>* expandedKey)
{
	for(int i = 0; i < 16; i++)state[i] = ciphertext[i];

	AddRoundKey(expandedKey + 160); //perform initial Addroundkey function
	
	for(int i = 8; i >= 0; i--) //perform all the inverse functions of AES 9 times
	{
		InvShiftRows();
 		InvSubBytes();
 		AddRoundKey(expandedKey + (16 * (i + 1))); //each round uses the next expanded key
 		InvMixColumns();
	} 

	//final round remove inverse mix colums
	InvShiftRows();
    InvSubBytes();
	AddRoundKey(expandedKey);
}


void AdvancedEncrypt::KeyExpansion(bitset<8>* key, bitset<8>* expandedKey)
{
	bitset<8> word[4], temp;    //stores the temp values sent to the gfunction
	for(int i = 0; i < 16; i++)	expandedKey[i] = key[i]; //the first 16 bytes are the original key are copied over
	int totalBytes = 16;  //keeps track of the amount of bytes we have created
	int round = 1;    //keeps track of the total number of 16 byte rounds

	while(totalBytes < 176)
	{
		for(int i = 0; i < 4; i++)
		{
			word[i] = expandedKey[i + totalBytes - 4];  // Read 4 bytes for processing in the gfunction
		}
		
		if(totalBytes % 16 == 0)
		{
			//gFunction(temp, round); //process bytes generated in the gfunction
			temp = word[0];
			for(int i = 0; i<3; i++)word[i] = word[i+1]; //rotate all the bytes in the word to the left
			word[3] = temp;

			for(int i = 0; i < 4; i++)word[i] = sbox[word[i].to_ulong()]; //substitute bytes to associated sbox values

			word[0] ^= rcon[round]; //XOR first byte with rcon corresponding round iteration
			round++;
		} 

		for(int a = 0; a < 4; a++)
		{
			expandedKey[totalBytes] = expandedKey[totalBytes - 16] ^ word[a]; // XOR temp with [totalBytes-16], and store in expandedKey
			totalBytes++;
		}
	}
}


bitset<8>* AdvancedEncrypt::getRoundState()
{
	return roundState;
}


bitset<8>* AdvancedEncrypt::getState()
{
	return state;
}
