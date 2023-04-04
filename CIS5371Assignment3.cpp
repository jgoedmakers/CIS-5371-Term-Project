/************************************************************************************************************************

Name:  James Goedmakers        Z#: Z23538628
Course: Practical Aspects of Modern Cryptography
Professor: Dr. Mehrdad Nojoumian
Due Date:  03/23/2023          Due Time: 11:59 PM
Total Points: 5
Assignment #: 3 - ElGamal Public-Key Encryption Implementation
Description: This program implements ElGamal Public-Key Encryption in C++

*************************************************************************************************************************/

//Include the following

#include <iostream>
#include <string>
#include <bitset>
#include <array>
#include <random>
#include <vector>

//library to handle large numbers
#include <boost/multiprecision/cpp_int.hpp>

using namespace boost::multiprecision;
using namespace std;

//Function Prototypes:

string getInput();
cpp_int power(cpp_int a,cpp_int b);
cpp_int squareMultiply(cpp_int a,cpp_int b,cpp_int n);
string millerRabin(int n, int t);

//Function Implementations:

/*************************************************************************************************************************************************/
//Name: getInput
//Decription: Gets input message and encryption key from user.
/***********************************************************************************************************************************************/
string getInput()
{
	string message;
	cout << "\nTesting getInput function.\n";
    cout << "Enter the message you would like to encrypt: \n";
	cin >> message;
	cout << "Your input is " << message << endl;
	return message;
}

/*************************************************************************************************************************************************/
//Name: power
//Decription: Returns a large number 'a' raised to the power 'b'
/***********************************************************************************************************************************************/
cpp_int power(cpp_int a,cpp_int b)
{
	cpp_int result = 1;
	for(unsigned i = 0;i<b;i++) {
		result *= a;
	}

	return result;
}

/*************************************************************************************************************************************************/
//Name: squareMultiply
//Decription: Outputs a^k (mod n)
/***********************************************************************************************************************************************/
cpp_int squareMultiply(cpp_int a,cpp_int k, cpp_int n)
{
	//get binary representation of k:
	vector<int> binary;
	cpp_int remainder, quotient, oldquotient;
	remainder = k % 2;
	quotient = k / 2;
	binary.push_back(int(remainder));
	cout << k << " = 2 x " << quotient << " + " << remainder << endl;
	while(quotient >= 1) {
		oldquotient = quotient;
		remainder = quotient % 2;
		quotient /= 2;
		binary.push_back(int(remainder));
		cout << oldquotient << " = 2 x " << quotient << " + " << remainder << endl;
	}

	reverse(binary.begin(), binary.end());

	cout << "Binary representation of " << k << " = " << endl;
	for(int i = 0;i<binary.size();i++) {
		cout << binary[i];
	}

	//ISSUE: this is not returning the correct output
	cpp_int b = 1;
	if(k == 0) {return b;}
	cpp_int A = a;
	if(binary[binary.size()-0] == 1) {b = a;}
	for(int i = 1;i<binary.size();i++) {
		A = A*A % n;
		if(binary[binary.size()-i] == 1) {b = A*b % n;}
	}
	return b;
}

/*************************************************************************************************************************************************/
//Name: millerRabin
//Decription: Generates a large prime number using input n and security parameter t
/***********************************************************************************************************************************************/
string millerRabin(int n, int t)
{
	//input: odd integer n >= 3, security parameter t >= 1
	if((n < 3) or ((n % 2) == 0)) {
		cout << "Error, invalid value for n." << endl;
		return "Error";
	}
	if(t < 1) {
		cout << "Error, invalid value for t." << endl;
		return "Error";
	}

	// n-1 = (2^s) * r
	// n-1 is even, 2^s is odd, r is even
	int s = 1;
	int quotient = (n-1) / 2;
	while(quotient % 2 == 0) {
		quotient /= 2;
		s++;
	}
	int r = quotient;
	cout << n << " - 1 = " << n-1 << " = 2^" << s << " * " << r << endl;


	//ISSUE: this part is not properly determining primality
	//for i=1 to t:
	for(int i = 0;i<t;i++) {
		//choose random integer a where 2<=a<=n-2
		int a = rand() % (n-2) + 2;
		//compute y=a^r (mod n) using squaremultiply
		//using pow() while squaremultiply is being fixed
		int y = pow(a,r);
		y = y % n;
		//if y != 1 and y != n-1:
		if((y != 1) and (y != n-1)) {
			//j=1
			int j = 1;
			//while j <= s-1 and y != n-1 do:
			while((j <= s-1) and (y != n-1)) {
			//y=y^2 (mod n)
			y = (y*y) % n;
			//if y=1 then return "composite"
			if(y == 1) {return "composite";}
			//j=j+1
			j++;
			}
		}
		//if y != n-1 then return "composite"
		if(y != n-1) {return "composite";}
	}
	return "prime";
}

//Main Driver
int main()
{
	//Get input message and key size from user.
	//for this test, key size is static at 64
	//int keySize = 64;
	//getInput();

    //cout << "Your message is: " << message;

	//El Gamal Algorithm
	//STEP 1: using the key size, generate a large random prime number using miller-rabin
	//int prime = millerRabin(keySize);
	cpp_int p = 2357;

	//millerrabin test:
	cout << millerRabin(31, 100) << endl;

	//generate a "generator" alpha that can generate all numbers in your set to a power
	cpp_int alpha = 2;

	//STEP 2: generate a random integer a where 1<=a<=(p-2) and compute (alpha^a (mod p))
	//using square and multiply algorithm
	cpp_int a = 1751;

	//test square and multiply algorithm:
	cpp_int test = squareMultiply(alpha, a, p);
	cout << "\n Testing SquareMultiply, X = Alpha^a (mod p) = " << test << endl;

	//Public Key = (p,alpha,alpha^a)
	//Private Key = (a)

	//El Gamal Encryption:
	//Part A: get public key = (p,alpha,X) where X = alpha^a (mod p)
	cpp_int x = power(alpha,a) % p;
	cout << "\n X = Alpha^a (mod p) = " << x << endl;

	//Part B: represent your message m as integers in range {0~(p-1)}
	cpp_int m = 2035;
	//Part C: select random k where 1<=k<=p-2
	cpp_int k = 1520;
	//Part D: gamma = alpha^k (mod p) and delta = m x (alpha^a)^k (mod p)
	cpp_int gamma = power(alpha,k) % p;
	cout << "Gamma = alpha^k (mod p) = " << gamma << endl;
	cpp_int delta = m * power(x,k) % p;
	cout<< "Delta = m x (alpha^a)^k (mod p) = " << delta << endl;

	//Part E: cypher = (gamma, delta)


	//El Gamal Decryption:
	//you have your private key, a
	//find gamma^(p-1-a) (mod p)
	cpp_int dec = power(gamma,(p-1-a)) % p;
	cout << "Decrypt = " << dec << endl;
	//calculate gamma^-a x delta (mod p)
	cpp_int message = dec * delta % p;
	cout << "Message = " << message << endl;

	return 0;
}