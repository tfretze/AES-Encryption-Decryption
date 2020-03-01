//This class performs the functionality of AES
//The class will only work with an 128 bit inputs and a 128 bit key
//Programmer: Tomas Fretze C3200070
//Last Modified: 13/05/2019

#ifndef ADVANCEDENCRYPT_H //macro guard
#define ADVANCEDENCRYPT_H
#include <iostream>
#include <bitset>
#include "lookup.h" //utilise variables from lookup table to perform substitutions and xor operations
using namespace std;

class AdvancedEncrypt
{
	public:
		//Constructor
		//Preconditions: NIL
		//Postconditions: New instance of class created
		AdvancedEncrypt();

		//Destructor
		//Preconditions: NIL
		//Postconditions: NIL
		~AdvancedEncrypt();

		//ENCRYPTION
		//Complete encryption
		//Preconditions: Requires a plaintext to encrypt and Expandedkey
		//Postconditions: State has been transformed into ciphertext
		void AES_Encrypt0(bitset<8>* plaintext, bitset<8>* expandedKey);

		//Encryption with Subbytes removed
		//Preconditions: Requires a plaintext to encrypt and Expandedkey
		//Postconditions: State has been transformed into ciphertext
		void AES_Encrypt1(bitset<8>* plaintext, bitset<8>* expandedKey);

		//Encryption with Shift Rows removed
		//Preconditions: Requires a plaintext to encrypt and Expandedkey
		//Postconditions: State has been transformed into ciphertext
		void AES_Encrypt2(bitset<8>* plaintext, bitset<8>* expandedKey);

		//Encryption with Mix columns removed
		//Preconditions: Requires a plaintext to encrypt and Expandedkey
		//Postconditions: State has been transformed into ciphertext
		void AES_Encrypt3(bitset<8>* plaintext, bitset<8>* expandedKey);

		//Encryption with Add Round Key removed
		//Preconditions: Requires a plaintext to encrypt and Expandedkey
		//Postconditions: State has been transformed into ciphertext
		void AES_Encrypt4(bitset<8>* plaintext, bitset<8>* expandedKey);

		//Preconditions: State passed to Function
		//Postconditions: State transformed byte by byte according to s_box table value
		void SubBytes();

		//Preconditions: State passed to Function
		//Postconditions: The bytes in the state are shifted left row number times
		void ShiftRows();

		//Preconditions: State passed to function
		//Postconditions: Each byte of a column is mapped into a new value that is a function of all four bytes in that column.
		void MixColumns();

		//DECRYPTION
		//Complete Decryption
		//Preconditions: Requires a ciphertext to Decrypt and Expandedkey
		//Postconditions: State has been transformed into plaintext
		void AES_Decrypt(bitset<8>* ciphertext, bitset<8>* expandedKey);

		//Preconditions: State passed to Function
		//Postconditions: State transformed byte by byte according to inv_s_box table value
		void InvSubBytes();

		//Preconditions: State passed to Function
		//Postconditions: The bytes in the state are shifted right row number times
		void InvShiftRows();

		//Preconditions: State passed to function
		//Postconditions: Each byte of a column is mapped into a new value that is a function of all four bytes in that column.
		void InvMixColumns();

		//KEY 
		//Preconditions: State passed to Function
		//Postconditions: State is xored with the corresponding round key
		void AddRoundKey(bitset<8>* roundKey);

		//Preconditions: requires 4 byte word and Rcon round number
		//Postconditions: performs 3 operations to the word - a left rotation, byte substitution, and xor with RCON value
		void gFunction(bitset<8>* in,  int i);

		//Preconditions: key and empty expanded key array are passed to the function
		//Postconditions: key has been expanded from 1-128 bit key to 11-128 bit keys this expansion is stored in the expandedKeys array
		void KeyExpansion(bitset<8>* key, bitset<8>* expandedKey);

		//Preconditions: the round number of the state required
		//Postconditions: state is copied to roundState array which holds the state of all the rounds
		void copyState(int round);

		//Preconditions: NIL
		//Postconditions: returns the roundState Array
		bitset<8>* getRoundState();

		//Preconditions: NIL
		//Postconditions: returns the state Array
		bitset<8>* getState();

	private:
		bitset<8> state[16], tmp[16], roundState[160]; //stores the state and the state after each round, temp array for state
};
#include "AdvancedEncrypt.hpp"
#endif