#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <future>
#include "quadgram_analysis.h"

using namespace std;

extern float qgram[];

constexpr char int_to_char [26] = {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'};
constexpr double min_quadgram_score {-10000000000};

void delay(){

    //Add Delay
    for(int i=0;i<10000;++i){
        cout << "\r[+] Processing Request";
    }

}

string key_update (string key_for_enc_n_dec, int plaintext_length){
    string temp = "";
    int i {0};
    while(temp.length()!= plaintext_length) {
        temp = temp + key_for_enc_n_dec[i];
        ++i;
        if((i > 0) && ((i % (key_for_enc_n_dec.length())) == 0)){
            //Restart the sequence
            i = 0;
        }

    }
    return temp;
}

int encryption(int plaintext_ascii, int key) {

    int ciphertext {0};
	//Character by Character Encryption
    ciphertext = (plaintext_ascii + key)%26;

    return ciphertext;
}

int decryption(int ciphertext_ascii, int key) {

    int plaintext {0};
	//Character by Character Decryption
    plaintext = (ciphertext_ascii - key + 26)%26;

    return plaintext;
}

string integer_to_char (int ciphertext){

    string cipherchar = "";
    for (int i=0; i<26; ++i) {

        if(ciphertext == i) {
            cipherchar = int_to_char [i];
        }

    }
    return cipherchar;
}

string encrypting (string plaintext, string key) {
	string ciphertext = "";
	vector<int> ascii_value_plaintext {};
	vector<int> ascii_value_key {};
	size_t key_length {key.length()};
	size_t message_length {plaintext.length()};
	vector<int> cipher_ascii {};


    for(int i=0; i<message_length; ++i) {
        //Store Credentials as ASCII values
        ascii_value_plaintext.push_back((int)plaintext[i] - 65);
    }

    //Converting Key to cover plaintext
    if((key_length<message_length) || (key_length > message_length)) {
        //cout << "Key Length Cannot be Used" << endl;
        //delay();
        //cout << endl;
        //Key Repetition
        key = key_update(key, message_length);
        //cout << "The Updated key: " << key << endl;
    }

    // Converting Key String to ASCII
    for(int i=0; i<message_length; ++i) {
        //Store Credentials as ASCII values
        ascii_value_key.push_back((int)key[i] - 65);
    }

    //Encrypting Character by Character
    for(int i=0; i<message_length; ++i) {
        cipher_ascii.push_back(encryption (ascii_value_plaintext [i], ascii_value_key [i]));
    }
    //Integer to Character Conversion
    for(int i=0; i<message_length; ++i) {
        ciphertext = ciphertext + integer_to_char (cipher_ascii[i]);
    }
    
    
    return ciphertext;
}

string decrypting (string ciphertext, string key) {
	string plaintext = "";
	vector<int> ascii_value_ciphertext {}; 
	vector<int> ascii_value_key {}; 
	size_t key_length {key.length()}; 
	size_t message_length {ciphertext.length()}; 
	vector<int> plain_ascii {};

    for(int i=0; i<message_length; ++i) {
        //Store Credentials as ASCII values
        ascii_value_ciphertext.push_back((int)ciphertext[i] - 65);
    }
	
	//Converting Key to cover ciphertext
    if((key_length<message_length) || (key_length > message_length)) {
        //cout << "Key Length Cannot be Used" << endl;
        //delay();
        //Key Repetition
        key = key_update(key, message_length);
        //cout << "The Updated key: " << key << endl;
    }
	
	// Converting Key String to ASCII
    for(int i=0; i<message_length; ++i) {
        //Store Credentials as ASCII values
        ascii_value_key.push_back((int)key[i] - 65);
    }
    //Decrypting Character by Character
    for(int i=0; i<message_length; ++i) {
        plain_ascii.push_back(decryption (ascii_value_ciphertext [i], ascii_value_key [i]));
    }
    //Integer to Character Conversion
    for(int i=0; i<message_length; ++i) {
        plaintext = plaintext + integer_to_char (plain_ascii[i]);
    }   
    
	return plaintext;
}


double scoring_via_quadgram(const string text, const int len){
   int i;
    char temp[4];
    double score = 0;
    for (i=0;i<len-3;++i){
        temp[0]=text[i]-'A';
        temp[1]=text[i+1]-'A';
        temp[2]=text[i+2]-'A';
        temp[3]=text[i+3]-'A';
        score += qgram[17576*temp[0] + 676*temp[1] + 26*temp[2] + temp[3]];
        
    }
    return score;
}
string truncate_key (const string key, const int key_len) {
	string truncate_final_key = "";
	for (int i = 0; i< key_len; ++i) {
			truncate_final_key = truncate_final_key + key [i];
		}
	return truncate_final_key;
}


class VigenereText {
public:
	string encrypted, decrypted, key;
	size_t length;
	double score;
	VigenereText(string t, size_t l): encrypted{key_update(t,l)}, decrypted{key_update(t,l)}, length{l}, key{"AA"}, score{min_quadgram_score} {}
	VigenereText(string t): encrypted{t}, decrypted{t}, length{t.length()}, key{"AA"}, score{min_quadgram_score} {}
	VigenereText(): encrypted{}, decrypted{}, length{0}, key{"AA"}, score{min_quadgram_score} {}
	void read_decrypted() {cin >> decrypted; encrypted=decrypted; length=decrypted.length();}
	void read_encrypted() {cin >> encrypted; decrypted=encrypted; length=encrypted.length();}
	void encrypt(string k) {key=k; encrypted = encrypting(decrypted, key);}
	void encrypt() {cin >> key; encrypted = encrypting(decrypted, key);}
	void decrypt(string k) {key=k; decrypted = decrypting(encrypted,key);}
	void decrypt() {decrypted = decrypting(encrypted,key);}
	void quadgram_score(size_t l) {score = scoring_via_quadgram(decrypted,l);}
	void quadgram_score() {score = scoring_via_quadgram(decrypted,length);}
	void print_status() {
		cout << "Score: " << score << '\n';
		cout << "-----------------------------------\nKEY: " << key << "\nCiphertext: " << decrypted << "\n-----------------------------------\n";
	}
};


double decryption_key_attempt_score (const VigenereText &ciphertext, const int loc, const int i){
	string key_copy {ciphertext.key};
	key_copy[loc] =  int_to_char[i];
	key_copy = key_update(key_copy, ciphertext.length);
	return scoring_via_quadgram (decrypting (ciphertext.encrypted, key_copy), ciphertext.length);
}


string decryption_key_attempt (VigenereText &ciphertext, const int loc){

	double decryption_score_list[26];
	for (int i = 0; i < 26; ++i) {
		std::future<double> score = std::async(decryption_key_attempt_score, ciphertext, loc, i);
		decryption_score_list[i] = score.get();
	}
	
	int best_score_index = std::max_element(std::begin(decryption_score_list), std::end(decryption_score_list)) - std::begin(decryption_score_list);
	string return_key {ciphertext.key};
	return_key[loc] =  int_to_char[best_score_index];
	return return_key;
}
