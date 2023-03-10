/************************************************************************************************************************

Name:  James Goedmakers        Z#: Z23538628
Course: Practical Aspects of Modern Cryptography
Professor: Dr. Mehrdad Nojoumian
Due Date:  03/2/2023          Due Time: 11:59 PM
Total Points: 5
Assignment #: 2 - DES Implementation
Description: This program implements DES encryption in C++

*************************************************************************************************************************/

//Include the following

#include <iostream>
#include <string>
#include <bitset>
#include <array>

using namespace std;

//Function Prototypes:

string getInput();
array<bitset<48>,16> keygen(bitset<64> key, string mode);
bitset<32> sbox(bitset<48> xord);
bitset<32> feistel(bitset<48> subkey, bitset<32> right);
bitset<64> encryption(bitset<64> message, array<bitset<48>,16> encKeys);

//Function Implementations:

/*************************************************************************************************************************************************/
//Name: getInput
//Decription: Gets input message and encryption key from user.
/***********************************************************************************************************************************************/
string getInput()
{
	string message;
	cout << "\nTesting getInput function.\n";
	cin >> message;
	cout << "Your input is " << message << endl;
	return message;
}

/*************************************************************************************************************************************************/
//Name: keygen
//Decription: generates encryption or decryption keys for DES
//Inputs: 64 bit master key, enc/dec parameter
//Outputs: array of 16 DES encryption or decryption subkeys
/***********************************************************************************************************************************************/
array<bitset<48>,16> keygen(bitset<64> key, string mode)
{
	//if(mode=="enc") { cout << "\nEntering keygen function in encryption mode.\n";}
	//else if(mode=="dec") {cout << "\nEntering keygen function in decryption mode.\n";}
	//cout << "******************************" << endl;
	//cout << "Input key: " << bitset<64>(key) << endl;
	//for encryption key generation:
	//get 56 bit permutation of 64 bit master key using pc-1
	//pc-1 is a table of 1-64 values with multiples of 8 excluded

	//inititalize array of subkeys
	array<bitset<48>,16> subkeys;
	
	int pc1[7][8] = {
		{57,1,10,19,63,7,14,21},
		{49,58,2,11,55,62,6,13},
		{41,50,59,3,47,54,61,5},
		{33,42,51,60,39,46,53,28},
		{25,34,43,52,31,38,45,20},
		{17,26,35,44,23,30,37,12},
		{9,18,27,36,15,22,29,4}
	};

	//Output test for pc1 table
	/**
	cout << "PC1 Table: " << endl;
	for(int i=0;i<7;i++) {
		for(int j=0;j<8;j++) {
			cout << pc1[i][j] << ",";
		}
		cout << endl;
	}
	cout << endl;
	**/

	//iterate through the pc1 table, and for every value x in the table at position i,
	//set the i'th bit of the 56 bit permutation equal to the bit value at index x in the 
	//64 bit master key
	//example: position 8 of pc1 has a value of 9, so take the value at index 9 of the master
	//key and input it into position 8 for the 56 bit permutation key
	bitset<56> perm1;
	//cout << "Perm1 initialized: " << perm1 << endl;
	//NOTE: bitset indexing starts at 0 and goes right to left, 
	//but the permutation table indexes start at 1
	int k = 0;
	for(int i=0;i<7;i++) {
		for(int j=0;j<8;j++) {
				perm1[55-k] = key[63-(pc1[i][j]-1)];
				k++;
		}
	}

	//Output test for original 64 bit key compared to 56 bit permutation key
	//cout << "Original 64 bit key: " << key << endl;
	//cout << "Perm1 key: " << perm1 << endl;
	
	//from permutation you get 28 bit C0 (left half) and 28 bit D0 (right half)
	bitset<28> leftkey;
	bitset<28> rightkey;
	for(int i=0;i<28;i++) {
		rightkey[i] = perm1[i];
		leftkey[i] = perm1[i+28];
	}
	//cout << "Left key: " << leftkey << "\t";
	//cout << "Right key: " << rightkey << endl;
	//in rounds 1,2,9,16 both halfs Ci and Di are seperately rotated left one bit
	//in all other rounds, Ci and Di are separately rotated left two bits

	//for decryption key generation:
	//get 56 bit permutation of 64 bit master key using pc-1
	//rotate to the RIGHT instead of left
	//no rotation on round 1
	//1 bit rotation on rounds 2,9,16
	//2 bit rotation on all other rounds
	int roundshifts[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
	if(mode=="dec") {roundshifts[0]=0;}
	for(int i=0;i<16;i++) {
		//cout << "Round: " << i+1 << endl;
		//NOTE: there is definitely a better way to do left vs right rotates than
		//multiple if else statements
		if(roundshifts[i] == 1) {
			if(mode=="enc") {
				//cout << "Left Rotate 1 bit" << endl;
				int temp = leftkey[27-0];
				leftkey = (leftkey << 1);
				leftkey[27-27] = temp;
				temp = rightkey[27-0];
				rightkey = (rightkey << 1);
				rightkey[27-27] = temp;
			}
			else if(mode=="dec") {
				//cout << "Right Rotate 1 bit" << endl;
				int temp = leftkey[0];
				leftkey = (leftkey >> 1);
				leftkey[27] = temp;
				temp = rightkey[0];
				rightkey = (rightkey >> 1);
				rightkey[27] = temp;
			}
		}
		else if(roundshifts[i] == 2) {
			if(mode=="enc") {
				//cout << "Left Rotate 2 bits" << endl;
				int temp = leftkey[27-0];
				int temp2 = leftkey[27-1];
				leftkey = (leftkey << 2);
				leftkey[27-26] = temp;
				leftkey[27-27] = temp2;
				temp = rightkey[27-0];
				temp2 = rightkey[27-1];
				rightkey = (rightkey << 2);
				rightkey[27-26] = temp;
				rightkey[27-27] = temp2;
			}
			else if(mode=="dec") {
				//cout << "Right rotate 2 bits" << endl;
				int temp = leftkey[0];
				int temp2 = leftkey[1];
				leftkey = (leftkey >> 2);
				leftkey[26] = temp;
				leftkey[27] = temp2;
				temp = rightkey[0];
				temp2 = rightkey[1];
				rightkey = (rightkey >> 2);
				rightkey[26] = temp;
				rightkey[27] = temp2;
			}
		}
		//cout << "Leftkey shifted: " << leftkey << "\t";
		//cout << "Rightkey shifted: " << rightkey << endl;
		//after each bit rotation, input the resulting 56 bits into pc-2 permutation to get subkey
		//rejoin the left and right key halves into 56 bit key:
		bitset<56> rejoinedkey;
		for(int i=0;i<28;i++) {
			rejoinedkey[i] = rightkey[i];
			rejoinedkey[i+28] = leftkey[i];
		}
		//cout << "Left key: " << leftkey << "\t";
		//cout << "Right key: " << rightkey << endl;
		//cout << "Rejoined key: " << rejoinedkey << endl;
		//input 56 bit rejoined key into pc-2 permutation to get 48 bit subkey
		//pc2 is a table of values 1-56 with 8 numbers excluded
		int pc2[6][8] = {
			{14,3,23,16,41,30,44,46},
			{17,28,19,7,52,40,49,42},
			{11,15,12,27,31,51,39,50},
			{24,6,4,20,37,45,56,36},
			{1,21,26,13,47,33,34,29},
			{5,10,8,2,55,48,53,32},
		};
		bitset<48> subkey;
		//cout << "Subkey initialized: " << subkey << endl;
		int k = 0;
		for(int i=0;i<6;i++) {
			for(int j=0;j<8;j++) {
					subkey[47-k] = rejoinedkey[55-(pc2[i][j]-1)];
					k++;
			}
		}
		//cout << "Rejoined 56 bit key: " << rejoinedkey << endl;
		//cout << "48 bit subkey : " << subkey << endl;
		//remember for decryption the keys will be in the reverse order
		subkeys[i] = subkey;
	}

	//Output test the subkey array
	/**
	for(int i=0;i<16;i++) {
		cout << "Subkey " << i + 1 << ":\t" << subkeys[i] << endl;
	}
	**/

	return subkeys;
}

/*************************************************************************************************************************************************/
//Name: sbox
//Decription: takes 8 6-bit s boxes and converts them to 8 4-bit s boxes
//Inputs: 8 6-bit s boxes
//Outputs: 8 4-bit s boxes
/***********************************************************************************************************************************************/
bitset<32> sbox(bitset<48> xord)
{
	//cout << "\nEntering sbox function.\n";
	//cout << "****************************" << endl;
	//cout << "Input XOR'd: " << xord << endl;
	array<bitset<6>,8> sboxes;
	int index = 0;
	for(int i=0;i<8;i++) {
		for(int j=0;j<6;j++) {
			sboxes[i][5-j] = xord[47-index];
			index++;
		}
		//cout << "sbox number " << i+1 << ": " << sboxes[i] << endl;
	}


	//get sbox tables (8 tables total, 1 for each sbox)
	// S-box Table
    int s[8][4][16] = {
        { 14, 4,  13, 1, 2,  15, 11, 8,  3,  10, 6,  12, 5,
          9,  0,  7,  0, 15, 7,  4,  14, 2,  13, 1,  10, 6,
          12, 11, 9,  5, 3,  8,  4,  1,  14, 8,  13, 6,  2,
          11, 15, 12, 9, 7,  3,  10, 5,  0,  15, 12, 8,  2,
          4,  9,  1,  7, 5,  11, 3,  14, 10, 0,  6,  13 },
        { 15, 1,  8,  14, 6,  11, 3, 4,  9,  7,  2,  13, 12,
          0,  5,  10, 3,  13, 4,  7, 15, 2,  8,  14, 12, 0,
          1,  10, 6,  9,  11, 5,  0, 14, 7,  11, 10, 4,  13,
          1,  5,  8,  12, 6,  9,  3, 2,  15, 13, 8,  10, 1,
          3,  15, 4,  2,  11, 6,  7, 12, 0,  5,  14, 9 },
 
        { 10, 0,  9,  14, 6,  3,  15, 5,  1,  13, 12,
          7,  11, 4,  2,  8,  13, 7,  0,  9,  3,  4,
          6,  10, 2,  8,  5,  14, 12, 11, 15, 1,  13,
          6,  4,  9,  8,  15, 3,  0,  11, 1,  2,  12,
          5,  10, 14, 7,  1,  10, 13, 0,  6,  9,  8,
          7,  4,  15, 14, 3,  11, 5,  2,  12 },
        { 7,  13, 14, 3,  0,  6,  9,  10, 1,  2, 8,  5,  11,
          12, 4,  15, 13, 8,  11, 5,  6,  15, 0, 3,  4,  7,
          2,  12, 1,  10, 14, 9,  10, 6,  9,  0, 12, 11, 7,
          13, 15, 1,  3,  14, 5,  2,  8,  4,  3, 15, 0,  6,
          10, 1,  13, 8,  9,  4,  5,  11, 12, 7, 2,  14 },
        { 2,  12, 4, 1,  7,  10, 11, 6, 8,  5,  3,  15, 13,
          0,  14, 9, 14, 11, 2,  12, 4, 7,  13, 1,  5,  0,
          15, 10, 3, 9,  8,  6,  4,  2, 1,  11, 10, 13, 7,
          8,  15, 9, 12, 5,  6,  3,  0, 14, 11, 8,  12, 7,
          1,  14, 2, 13, 6,  15, 0,  9, 10, 4,  5,  3 },
        { 12, 1,  10, 15, 9,  2,  6,  8,  0,  13, 3, 4, 14,
          7,  5,  11, 10, 15, 4,  2,  7,  12, 9,  5, 6, 1,
          13, 14, 0,  11, 3,  8,  9,  14, 15, 5,  2, 8, 12,
          3,  7,  0,  4,  10, 1,  13, 11, 6,  4,  3, 2, 12,
          9,  5,  15, 10, 11, 14, 1,  7,  6,  0,  8, 13 },
        { 4,  11, 2,  14, 15, 0,  8, 13, 3,  12, 9,  7,  5,
          10, 6,  1,  13, 0,  11, 7, 4,  9,  1,  10, 14, 3,
          5,  12, 2,  15, 8,  6,  1, 4,  11, 13, 12, 3,  7,
          14, 10, 15, 6,  8,  0,  5, 9,  2,  6,  11, 13, 8,
          1,  4,  10, 7,  9,  5,  0, 15, 14, 2,  3,  12 },
        { 13, 2,  8, 4,  6,  15, 11, 1,  10, 9, 3, 14, 5,
          0,  12, 7, 1,  15, 13, 8,  10, 3,  7, 4, 12, 5,
          6,  11, 0, 14, 9,  2,  7,  11, 4,  1, 9, 12, 14,
          2,  0,  6, 10, 13, 15, 3,  5,  8,  2, 1, 14, 7,
          4,  10, 8, 13, 15, 12, 9,  0,  3,  5, 6, 11 }
    };

	//for every sbox, add the most and least significant bit together
	//the sum is the index of the specific sbox table row
	//the decimal conversion of the inner 4 bits is the column index
	//the value found in the table is the 4 bit number
	array<bitset<4>,8> newsboxes;
	int rowindex;
	int columnindex;
	for(int i=0;i<8;i++) {
		rowindex = sboxes[i][5] + sboxes[i][0];
		//cout << "Rowindex = " << sboxes[i][5] << " + " << sboxes[i][0] << " = " << rowindex << endl;
		columnindex = (sboxes[i][4]*8) + (sboxes[i][3]*4) + (sboxes[i][2]*2) + (sboxes[i][1]*1);
		//cout << "Columnindex = " << columnindex << endl;
		newsboxes[i] = s[i][rowindex][columnindex];
		//cout << "New sbox " << i+1 << ": " << newsboxes[i] << endl;

	}
	
	//rejoin sboxes into 32 bit bitset
	bitset<32> rejoined;
	index = 0;
	for(int i=0;i<8;i++) {
		for(int j=0;j<4;j++) {
			rejoined[31-index] = newsboxes[i][3-j];
			index++;
		}
	}
	//cout << "Rejoined newsboxes: " << rejoined << endl;
	return rejoined;
}

/*************************************************************************************************************************************************/
//Name: function
//Decription: 
//Inputs: R_i-1 and subkey_i
//Outputs: 32 bit output 
/***********************************************************************************************************************************************/
bitset<32> feistel(bitset<48> subkey, bitset<32> right)
{
	//cout << "\nEntering feistel function.\n";
	//cout << "******************************" << endl;
	//cout << "Subkey input: " << subkey << endl;
	//cout << "R_i-1 input: " << right << endl;

	//perform expansion on R_i-1:
	//expansion()
	//initialize expansion table
	int expand[8][6] {
		{32,1,2,3,4,5},
		{4,5,6,7,8,9},
		{8,9,10,11,12,13},
		{12,13,14,15,16,17},
		{16,17,18,19,20,21},
		{20,21,22,23,24,25},
		{24,25,26,27,28,29},
		{28,29,30,31,32,1}
	};

	bitset<48> expanded;
	//cout << "Expanded initialized: " << expanded << endl;
	//NOTE: bitset indexing starts at 0 and goes right to left, 
	//but the permutation table indexes start at 1
	int k = 0;
	for(int i=0;i<8;i++) {
		for(int j=0;j<8;j++) {
				expanded[47-k] = right[47-(expand[i][j]-1)];
				k++;
		}
	}
	//cout << "Expanded: " << expanded << endl;
	//XOR the expansion of R_i-1 with 48 bit subkey_i
	bitset<48> xord = expanded ^ subkey;
	//cout << "XOR'd: " << xord << endl;
	//partition the result into 8 separate 6-bit s boxes
	//reduce each 6-bit s box into 4-bit s boxes
	//take the remaining 32 bits from the 8 4-bit s boxes and perform permutation III with them
	bitset<32> sboxjoined = sbox(xord);
	
	//initialize perm table
	int perm[4][8] = {
		{16,7,20,21,29,12,28,17},
		{1,15,23,26,5,18,31,10},
		{2,8,24,14,32,27,3,9},
		{19,13,30,6,22,11,4,25}
	};

	bitset<32> shuffled;
	int index = 0;
	for(int i=0;i<4;i++) {
		for(int j=0;j<8;j++) {
				shuffled[31-index] = sboxjoined[31-(perm[i][j]-1)];
				index++;
		}
	}
	//cout << "sbox rejoined: " << sboxjoined << endl;
	//cout << "shuffled 32 bit: " << shuffled << endl;

	return shuffled;
	
}

/*************************************************************************************************************************************************/
//Name: encryption
//Decription: encrpytion portion of DES
//Inputs: message and key
//Outputs: ciphertext
/***********************************************************************************************************************************************/
bitset<64> encryption(bitset<64> message, array<bitset<48>,16> subkeys)
{
	//cout << "\nEntering encryption function.\n";
	//cout << "***********************************" << endl;

	//cout << "Message block: " << message << endl;
	//get initial permutation of message (see block I)
	//initialize initial permutation table
	//8x8 matrix with values 1-64
	int ip[8][8] = {
		{58,50,42,34,26,18,10,2},
		{60,52,44,36,28,20,12,4},
		{62,54,46,38,30,22,14,6},
		{64,56,48,40,32,24,16,8},
		{57,49,41,33,25,17,9,1},
		{59,51,43,35,27,19,11,3},
		{61,53,45,37,29,21,13,5},
		{63,55,47,39,31,23,15,7}
	};
	//perform initial permutation of 64 bit message into 64 bit permutation
	bitset<64> perm1;
	//cout << "Perm1 initialized: " << perm1 << endl;
	//NOTE: bitset indexing starts at 0 and goes right to left, 
	//but the permutation table indexes start at 1
	int k = 0;
	for(int i=0;i<8;i++) {
		for(int j=0;j<8;j++) {
				perm1[63-k] = message[63-(ip[i][j]-1)];
				k++;
		}
	}
	//cout << "Initial Permutation: " << perm1 << endl;
	//divide initial message permutation into 32 bit L0 (left half) and R0 (right half)
	bitset<32> left;
	bitset<32> right;
	for(int i=0;i<32;i++) {
		right[i] = perm1[i];
		left[i] = perm1[i+32];
	}
	//cout << "Left half: " << left << "\t";
	//cout << "Right half: " << right << endl;
	bitset<32> newleft;
	bitset<32> newright;
	//for 16 rounds, perform the following:
	for(int i=0;i<16;i++) {
		//cout << "Old left: " << left << endl;
		//cout << "Old right: " << right << endl;
		//L1 = R0
		newleft = right;

		//R1 = L0 XOR f(subkey-i,R0) (see block III)
		newright = left ^ feistel(subkeys[i],right);

		left = newleft;
		right = newright;
		//cout << "New left: " << newleft << endl;
		//cout << "New right: " << newright << endl;
	}

	//get final permutation from L16 and R16 (see block 2)
	//NOTE: notes from class show swapping L16 and R16's 
	//positions before rejoining and final permutation
	//rejoin the left and right halves:
	bitset<64> rejoined;
	for(int i=0;i<32;i++) {
		rejoined[i] = left[i];
		rejoined[i+32] = right[i];
	}
	//cout << "Rejoined 64 bit: " << rejoined << endl;
	//initialize final permutation table
	//8x8 matrix with values 1-64
	int fp[8][8] = {
		{40,8,48,16,56,24,64,32},
		{39,7,47,15,55,23,63,31},
		{38,6,46,14,54,22,62,30},
		{37,5,45,13,53,21,61,29},
		{36,4,44,12,52,20,60,28},
		{35,3,43,11,51,19,59,27},
		{34,2,42,10,50,18,58,26},
		{33,1,41,9,49,17,57,25}
	};

	bitset<64> permfinal;
	k = 0;
	for(int i=0;i<8;i++) {
		for(int j=0;j<8;j++) {
				permfinal[63-k] = rejoined[63-(fp[i][j]-1)];
				k++;
		}
	}
	//cout << "Final Permutation: " << permfinal << endl;
	return permfinal;
}

//Main Driver
int main()
{
	//Part 1: Get input message and key from user.
	//Convert message into 64 bit binary blocks for the DES encryption/decryption
	//void getInput();
	//getInput();

	//for testing, use a static message and key value
	//each block of the message must be 64 bits
	bitset<64> message = 0b1000101011000111001000110000010010001001111010000000000000000000;
	cout << "Input Message : " << message << endl;
	//the master key starts off as 64 bits
	bitset<64> key = 0b1000101011000111001000110000010010001001111010000000000000000000;
	cout << "Input Key: " << key << endl;

	//Part 2: Encrypt message using DES method.
	//call keygen function to generate encryption subkeys
	string mode = "enc";
	array encKeys = keygen(key, mode);
	//Output check the encryption subkeys
	/**
	for(int i=0;i<16;i++) {
		cout << "Subkey " << i + 1 << ":\t" << encKeys[i] << endl;
	}
	**/
	//Call encryption function using the subkeys and message
	bitset<64> cypher;
	cypher = encryption(message, encKeys);
	//Output check the encrypted cyphertext
	cout << "Encrypted Cypher: " << cypher << endl;

	//Part 3: Decrypt the message using DES method.
	//call keygen to generate decryption subkeys
	mode = "dec";
	array decKeys = keygen(key, mode);
	//Output check the decryption subkeys
	/**
	for(int i=0;i<16;i++) {
		cout << "Subkey " << i + 1 << ":\t" << decKeys[i] << endl;
	}
	**/	
	//Output the decrypted message block
	bitset<64> decrypted;
	decrypted = encryption(cypher, decKeys);
	cout << "Decrypted cypher: " << decrypted << endl;

	//Part 4: Combine the decrypted message blocks to get the complete decrypted message
	//output();


	//Tests for common DES bitwise operations:
	/**
	int a = 0b0101;
	int b = 0b1010;
	//XOR:
	int c = a^b;
	std::cout << "a = " << std::bitset<4>(a)  << std::endl;
    std::cout << "b = " << std::bitset<4>(b)  << std::endl;
    std::cout << "a XOR b = " << std::bitset<4>(c) << std::endl;
	//Bitshift:
	int d = (c << 1);
	cout << bitset<4>(d) << endl;
	//Bit modification:
	bitset<4> e = 0b1111;
	cout << e << endl;
	e[3] = 0;
	cout << e << endl;
	**/
	

	return 0;
}