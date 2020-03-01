//Assignment 2: AES Implementation
//Author: Tomas Fretze
//Last Modified: 12/05/2019
//Program Description: This program demonstrates the functionality of an AES Encryption Implementation

#include <iostream>
#include <iomanip>
#include <cmath>
#include <fstream>
#include <string>
using namespace std;
#include "AdvancedEncrypt.h" //Includes all AES methods

//Preconditions: Requires filename and creation of empty bitset arrays 
//Postconditions: Reads from input text file and stores values from text file in 2 arrays for message and key
void readFile(bitset<8>* m, bitset<8>* k, string fileName)
{
	cout<<"Reading "<< fileName<<"...";
	string input;
	ifstream infile;
	infile.open (fileName); //opens requested text file

	getline(infile, input); //copies first line to string
	for(int i = 0; i < 16; i++)
	{
		m[i] = bitset<8>(input.substr(i*8, (i+1)*8)); //copies line to message array
	}
	getline(infile, input); //retrieves next line and stores in string
	for(int i = 0; i < 16; i++)
	{	
		k[i] = bitset<8>(input.substr(i*8, (i+1)*8)); //copies line to key array
	}
	infile.close();
	cout<<"complete"<<endl;
}

//Preconditions: requires the message to be encrypted and the avalanche effect averages to be calculated
//Postconditions: Writes results to a text file called OutputEncrypt.txt
void outputEncrypt(bitset<8>* m, bitset<8>* k, bitset<8>* c, double* a, clock_t time)
{
	cout<<"Writing OutputEncrypt.txt...";
	ofstream myfile ("OutputEncrypt.txt");
  	if (myfile.is_open())
  	{
	    myfile << "ENCRYPTION";
	    myfile << "\nPlaintext P: "; for(int i = 0; i<16; i++){myfile<<m[i]<<" ";} 
	    myfile << "\nKey K: "; for(int i = 0; i<16; i++){myfile<<k[i]<<" ";}
	    myfile << "\nCiphertext C: "; for(int i = 0; i<16; i++){myfile<<c[i]<<" ";}
	    myfile << "\nRunning Time: "<<  (clock() - time)/1000.0<< "seconds";
	    myfile << "\nAvalanche: ";
	    myfile << "\nP and Pi Under K";
	    myfile << "\nRound   AES0   AES1   AES2   AES3   AES4"; //loops through the averages array and outputs all results to table
	    myfile << "\n 0       1      1      1      1      1  ";
	    for(int i = 0; i < 10; i++)
	    {
	    	myfile << "\n" <<setw(2)<< i+1 <<setw(8)<<(int)round(a[i])<<setw(7)<<(int)round(a[i+10])<<setw(7)<<(int)round(a[i+20])<<setw(7)<<(int)round(a[i+30])<<setw(7)<<(int)round(a[i+40]);
	    } 
	    myfile << "\nP Under K and Ki";
	    myfile << "\nRound   AES0   AES1   AES2   AES3   AES4";
	    myfile << "\n 0       0      0      0      0      0  ";
	    for(int i = 0; i < 10; i++)
	    {
	    	myfile << "\n" <<setw(2)<< i+1 <<setw(8)<<(int)round(a[i+50])<<setw(7)<<(int)round(a[i+60])<<setw(7)<<(int)round(a[i+70])<<setw(7)<<(int)round(a[i+80])<<setw(7)<<(int)round(a[i+90]);
	    } 
	    myfile.close();
  	}
	else cout << "Unable to open file";
	cout<<"complete"<<endl;
}

//Preconditions: the message has been decrypted and all decryption arrays are passed to function
//Postconditions:  Writes results to a text file called OutputDecrypt.txt
void outputDecrypt(bitset<8>* c, bitset<8>* k, bitset<8>* m)
{
	cout<<"Writing OutputDecrypt.txt...";
	ofstream myfile ("OutputDecrypt.txt");
  	if (myfile.is_open())
  	{
	    myfile << "DECRYPTION";
	    myfile << "\nCiphertext C: "; for(int i = 0; i<16; i++){myfile<<c[i]<<" ";}
	    myfile << "\nKey K: "; for(int i = 0; i<16; i++){myfile<<k[i]<<" ";}
	    myfile << "\nPlaintext P: "; for(int i = 0; i<16; i++){myfile<<m[i]<<" ";} 
	    myfile.close();
  	}
	else cout << "Unable to open file";
	cout<<"complete"<<endl<<"All tasks completed successfully";
}


int main()
{		
	clock_t t = clock();
	AdvancedEncrypt *state[15]; //created enough states for 5 x 3 different encryptions
	for(int i = 0; i < 15; i++)
	{
		state[i] = new AdvancedEncrypt(); //initialise each of the states
	}
	int avalanche[128][100] = {0};  //array for storing the bit difference for each round of the Avalanche analysis
	double average[100] = {0};    //array for storing the average of all the avalanche analysis results
	// string input;
	bitset<8> message0[16], message1[16], key0[16], key1[16], expandedKey0[176], expandedKey1[176]; //arrays for storing the different keys and messages
	readFile(message0, key0, "InputEncrypt.txt");
	for (int i = 0; i < 16; i++) //set p1 and k1 to message these arrays will be used to create avalanche analysis
	{
		message1[i] = message0[i];
		key1[i] = key0[i];
	}
	//perform key expansion to obtain expandedKey0 
	cout<<"Performing Encryption...";
	state[0]->KeyExpansion(key0, expandedKey0);

	//plaintext P under key K for all 5 rounds
	state[0]->AES_Encrypt0(message0, expandedKey0); 
	state[1]->AES_Encrypt1(message0, expandedKey0);
	state[2]->AES_Encrypt2(message0, expandedKey0);
	state[3]->AES_Encrypt3(message0, expandedKey0);
	state[4]->AES_Encrypt4(message0, expandedKey0);
	cout<<"complete"<<endl;
    
	//AVALANCHE ANALYSIS LOOP
	cout<<"Performing Avalanche Analysis...";
    for(int i = 0; i < 128; i++) //iterates through 128 versions of the message and key 
	{
		for(int i = 0; i <176; i++)
		{
			expandedKey1[i] = 0;
		}
		message1[i/16] = message0[i/16] ^ (bitset<8>)pow(2,i%8); //change every bit of the message once and store in array
		key1[i/16] = key0[i/16] ^ (bitset<8>)pow(2,i%8); //change every bit of the key once and store in array
		if(i%16 == 0 && i > 1)
		{
			message1[(i-1)/16] = message0[(i-1)/16]; //removes any changes from the previous byte
			key1[(i-1)/16] = key0[(i-1)/16]; //removes any changes from previous byte
		}
		state[1]->KeyExpansion(key1, expandedKey1);

		// //plaintext P under key K1 for all 5 rounds
		state[5]->AES_Encrypt0(message0, expandedKey1);
		state[6]->AES_Encrypt1(message0, expandedKey1);
		state[7]->AES_Encrypt2(message0, expandedKey1);
		state[8]->AES_Encrypt3(message0, expandedKey1);
		state[9]->AES_Encrypt4(message0, expandedKey1);

		// // //plaintext P1 under key K for all 5 rounds
		state[10]->AES_Encrypt0(message1, expandedKey0);
		state[11]->AES_Encrypt1(message1, expandedKey0);
		state[12]->AES_Encrypt2(message1, expandedKey0);
		state[13]->AES_Encrypt3(message1, expandedKey0);
		state[14]->AES_Encrypt4(message1, expandedKey0);

		for(int j = 0; j < 10; j++) 
		{
			for(int k = 0; k < 16; k++) 
			{   
				//round state of the original message is xor'd with the round state of the message with one bit changed and added to avalanche array
				avalanche[i][j] += (state[0]->getRoundState()[k+(j*16)] ^ state[10]->getRoundState()[k+(j*16)]).count();
				avalanche[i][j+10] += (state[1]->getRoundState()[k+(j*16)] ^ state[11]->getRoundState()[k+(j*16)]).count();
				avalanche[i][j+20] += (state[2]->getRoundState()[k+(j*16)] ^ state[12]->getRoundState()[k+(j*16)]).count();
				avalanche[i][j+30] += (state[3]->getRoundState()[k+(j*16)] ^ state[13]->getRoundState()[k+(j*16)]).count();
				avalanche[i][j+40] += (state[4]->getRoundState()[k+(j*16)] ^ state[14]->getRoundState()[k+(j*16)]).count();
				
				//round state of the original message using original key is xor'd with the round state of the message using key with one bit changed  with one bit changed and added to avalanche array
				avalanche[i][j+50] += (state[0]->getRoundState()[k+(j*16)] ^ state[5]->getRoundState()[k+(j*16)]).count();
				avalanche[i][j+60] += (state[1]->getRoundState()[k+(j*16)] ^ state[6]->getRoundState()[k+(j*16)]).count();
				avalanche[i][j+70] += (state[2]->getRoundState()[k+(j*16)] ^ state[7]->getRoundState()[k+(j*16)]).count();
				avalanche[i][j+80] += (state[3]->getRoundState()[k+(j*16)] ^ state[8]->getRoundState()[k+(j*16)]).count();
				avalanche[i][j+90] += (state[4]->getRoundState()[k+(j*16)] ^ state[9]->getRoundState()[k+(j*16)]).count();
			}
		}
	}

	//all results are added and then averaged and stored into average array
	for(int i = 0; i<100; i++)
	{
		for(int j = 0; j<128; j++)
		{
			average[i] += avalanche[j][i];
		}
		average[i] /= 128.0;
	}
	cout<<"complete"<<endl;


	//send the original plaintext, the original key, the ciphertext and the average arrays to the output function
	outputEncrypt(message0, key0, state[0]->getState(), average, t);

	//decrypt message
	
	readFile(message0, key0, "InputDecrypt.txt"); //read values from input file
	cout<<"Performing Decryption...";
	state[0]->KeyExpansion(key0, expandedKey0); //send key to be expanded
	state[0]->AES_Decrypt(message0, expandedKey0); //send message to be decrypted
	//send the cyphertext message, key and the decrypted plaintext arrays to the output function
	cout<<"complete"<<endl;
	outputDecrypt(message0, key0, state[0]->getState());	
	return 0;
}
//testing

//cout<<"Encrypted Message:"<<endl;	
// for(int i = 0; i < 16; i++)
// {
// 	cout << hex << state[0]->getState()[i].to_ulong()<< " ";
// }
// cout<<endl <<endl;

//testing
//cout<<"Decrypted Message:"<<endl; 
// for(int i = 0; i < 16; i++)
// {
// 	cout << hex << state[0]->getState()[i].to_ulong()<<" ";
// }
	

