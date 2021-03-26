//Free to use and distribute
#include <iostream>
#include <string>
#include <chrono>
#include "vigenere.h"

// KEY1: STRINGLENGTHOFTHIRTYCHARACTERS
// KEY2: CRYPTOGRAPHYISWHATWEARESTUDYING
// KEY3: PRAISEBETOTHELORDFORHEHASHEARDMYCRYFORMERCY
// KEY4: ONEOFTHEBESTTELEVISIONSHOWSISPEAKYBLINDERSNODOUBT SUBSTITUTION

// KEY: HELLO HELLO HELLO HELLO HELLO HELLO HELLO HELLO HELLO HELLO HELLO HELLO HELLO HELLO HELLO HELLO HELLO HELLO HELLO HELLO HELLO HELLO HELLO HEL
// PLA: HELPM EDEAR BRYAN HELPM EBROT HERIA MREAC HINGO UTMYW IFELE FTMEI AMALL ALONE BRIAN DOVIS ITMEI AMALL SADAN DALON EIFEE LLIKE CRYIN GBROT HER
// CIP: TEYAK QDRLP NRLLL TEYAK QBEZR TEETY YRRLA TIARM GTZJU UFRWC RTZPG MMNWJ MLBYC NRVLL POITQ UTZPG MMNWJ EAQLL PAYZL QISPC XLVVC ORLTL S
// PLAINTEXT: HELPMEDEARBRYANHELPMEBROTHERIAMREACHINGOUTMYWIFELEFTMEIAMALLALONEBRIANDOVISITMEIAMALLSADANDALONEIFEELLIKECRYING
//CIPHERTEXT: TEYAKQDRLPNRLLLTEYAKQBEZRTEETYYRRLATIARMGTZJUUFRWCRTZPGMMNWJMLBYCNRVLLPOITQUTZPGMMNWJEAQLLPAYZLQISPCXLVVCORLTLS
//			: MANLY MANLY MANLY MANLY MANLY MANLY MANLY MANLY MANLY M
// Plaintext: HELPM EDEAR AWERT OYKFM BRYAN HELPM EBROT HMJGE FALMS Y ERIAMREACHINGOUTMYWIFELEFTMEIAMALLALONEBRIANDOVISITMEIAMALLSADANDALONEIFEELLIKECRYINGBROTHER
// Ciphertex: TEYAK QDRLP MWRCR AYXQK NRLLL TEYAK QBEZR T  
//			  TEYAK QDRLP MWRCR AYXQK NRLLL TEYAK QBEZR TMWRC RAYXQ KEETY YRRLA TIARM GTZJU UFRWC RTZPG MMNWJ MLBYC NRVLL POITQ UTZPG MMNWJ EAQLL PAYZL QISPC XLVVC ORLTL S

string text_trim_expand(int encrypted_text_length, string compare_text) {
	
	string return_text = "";
	auto compare_text_length = compare_text.length();
	if(compare_text_length > encrypted_text_length){
		
		for(auto i=0; i < encrypted_text_length; i++) {
			return_text += compare_text[i];
		}
		
	}
	else{
		if(compare_text_length < encrypted_text_length) {
			for(auto i=0; i < encrypted_text_length; i++) {
				return_text += compare_text[i%compare_text_length];
			}
		}
		else{
			return_text = compare_text; 
		}
	}
	
	return return_text;
	
}

void vigenere_analysis(VigenereText &ciphertext) {
	
	ciphertext.quadgram_score();
	
	//responsible for resizing and cryptanalysis
	string base_text = "THEEUROPEANLANGUAGESAREMEMBERSOFTHESAMEFAMILYTHEIRSEPARATEEXISTENCEISAMYTHFORSCIENCEMUSICSPORTETCEUROPEUSESTHESAMEVOCABULARYTHELANGUAGESONLYDIFFERINTHEIRGRAMMARTHEIRPRONUNCIATIONANDTHEIRMOSTCOMMONWORDSEVERYONEREALIZESWHYANEWCOMMONLANGUAGEWOULDBEDESIRABLEONECOULDREFUSETOPAYEXPENSIVETRANSLATORSTOACHIEVETHISITWOULDBENECESSARYTOHAVEUNIFORMGRAMMARPRONUNCIATIONANDMORECOMMONWORDSIFSEVERALLANGUAGESCOALESCETHEGRAMMAROFTHERESULTINGLANGUAGEISMORESIMPLEANDREGULARTHANTHATOFTHEINDIVIDUALLANGUAGESTHENEWCOMMONLANGUAGEWILLBEMORESIMPLEANDREGULARTHANTHEEXISTINGEUROPEANLANGUAGESITWILLBEASSIMPLEASOCCIDENTALINFACTITWILLBEOCCIDENTALTOANENGLISHPERSONITWILLSEEMLIKESIMPLIFIEDENGLISHASASKEPTICALCAMBRIDGEFRIENDOFMINETOLDMEWHATOCCIDENTALISTHEEUROPEANLANGUAGESAREMEMBERSOFTHESAMEFAMILYTHEIRSEPARATEEXISTENCEISAMYTHFORSCIENCEMUSICSPORTETCEUROPEUSESTHESAMEVOCABULARYTHELANGUAGESONLYDIFFERINTHEIRGRAMMARTHEIRPRONUNCIATIONANDTHEIRMOSTCOMMONWORDSEVERYONEREALIZESWHYANEWCOMMONLANGUAGEWOULDBEDESIRABLEONECOULDREFUSETOPAYEXPENSIVETRANSLATORSTOACHIEVETHISITWOULDBENECESSARYTOHAVEUNIFORMGRAMMARPRONUNCIATIONANDMORECOMMONWORDSIFSEVERALLANGUAGESCOALESCETHEGRAMMAROFTHERESULTINGLANGUAGEISMORESIMPLEANDREGULARTHANTHATOFTHEINDIVIDUALLANGUAGESTHENEWCOMMONLANGUAGEWILLBEMORESIMPLEANDREGULARTHANTHEEXISTINGEUROPEANLANGUAGESITWILLBEASSIMPLEASOCCIDENTALINFACTITWILLBEOCCIDENTALTOANENGLISHPERSONITWILLSEEMLIKESIMPLIFIEDENGLISHASASKEPTICALCAMBRIDGEFRIENDOFMINETOLDMEWHATOCCIDENTALISTHEEUROPEANLANGUAGESAREMEMBERSOFTHESAMEFAMILYTHEIRSEPARATEEXISTENCEISAMYTHFORSCIENCEMUSICSPORTETCEUROPEUSESTHESAMEVOCABULARYTHELANGUAGESONLYDIFFERINTHEIRGRAMMARTHEIRPRONUNCIATIONANDTHEIRMOSTCOMMONWORDSEVERYONEREALIZESWHYANEWCOMMONLANGUAGEWOULDBEDESIRABLEONECOULDREFUSETOPAYEXPENSIVETRANSLATORSTOACHIEVETHISITWOULDBENECESSARYTOHAVEUNIFORMGRAMMARPRONUNCIATIONANDMORECOMMONWORDSIFSEVERALLANGUAGESCOALESCETHEGRAMMAROFTHERESULTINGLANGUAGEISMORESIMPLEANDREGULARTHANTHATOFTHEINDIVIDUALLANGUAGESTHENEWCOMMONLANGUAGEWILLBEMORESIMPLEANDREGULARTHANTHEEXISTINGEUROPEANLANGUAGESITWILLBEASSIMPLEASOCCIDENTALINFACTITWILLBEOCCIDENTALTOANENGLISHPERSONITWILLSEEMLIKESIMPLIFIEDENGLISHASASKEPTICALCAMBRIDGEFRIENDOFMINETOLDMEWHATOCCIDENTALISTHEEUROPEANLANGUAGESAREMEMBERSOFTHESAMEFAMILYTHEIRSEPARATEEXISTENCEISAMYTHFORSCIENCEMUSICSPORTETCEUROPEUSESTHESAMEVOCABULARYTHELANGUAGESONLYDIFFERINTHEIRGRAMMARTHEIRPRONUNCIATIONANDTHEIRMOSTCOMMONWORDSEVERYONEREALIZESWHYANEWCOMMONLANGUAGEWOULDBEDESIRABLEONECOULDREFUSETOPAYEXPENSIVETRANSLATORSTOACHIEVETHISITWOULDBENECESSARYTOHAVEUNIFORMGRAMMARPRONUNCIATIONANDMORECOMMONWORDSIFSEVERALLANGUAGESCOALESCETHEGRAMMAROFTHERESULTINGLANGUAGEISMORESIMPLEANDREGULARTHANTHATOFTHEINDIVIDUALLANGUAGESTHENEWCOMMONLANGUAGEWILLBEMORESIMPLEANDREGULARTHANTHEEXISTINGEUROPEANLANGUAGESITWILLBEASSIMPLEASOCCIDENTALINFACTITWILLBEOCCIDENTALTOANENGLISHPERSONITWILLSEEMLIKESIMPLIFIEDENGLISHASASKEPTICALCAMBRIDGEFRIENDOFMINETOLDMEWHATOCCIDENTALISTHEEUROPEANLANGUAGESAREMEMBERSOFTHESAMEFAMILYTHEIRSEPARATEEXISTENCEISAMYTHFORSCIENCEMUSICSPORTETCEUROPEUSESTHESAMEVOCABULARYTHELANGUAGESONLYDIFFERINTHEIRGRAMMARTHEIRPRONUNCIATIONANDTHEIRMOSTCOMMONWORDSEVERYONEREALIZESWHYANEWCOMMONLANGUAGEWOULDBEDESIRABLEONECOULDREFUSETOPAYEXPENSIVETRANSLATORSTOACHIEVETHISITWOULDBENECESSARYTOHAVEUNIFORMGRAMMARPRONUNCIATIONANDMORECOMMON";
	
	VigenereText compare {base_text, ciphertext.length};
	auto ciphertext_length = ciphertext.encrypted.length();
	
	
	compare.quadgram_score();
	
	cout << "Compare Score: " << compare.score << '\n';
	cout << "Score of the ciphertext: " << ciphertext.score << '\n' << "-----------------------------------" << '\n';
	
	size_t best_key_length {ciphertext.length};
	double highest_score {min_quadgram_score};
	auto start = chrono::steady_clock::now();
	for (int key_length = 2; key_length < ciphertext.length; ++key_length) {
		
		//Try not to repeat keys
		if (key_length > 2*best_key_length) break;
		
		//Guessing Keys character by character
		for (int i = 0; i < key_length; ++i) {
			ciphertext.key = decryption_key_attempt (ciphertext.encrypted,i,ciphertext.key);
			ciphertext.decrypted = decrypting (ciphertext.encrypted,ciphertext.key);
			ciphertext.quadgram_score();
			if ((highest_score < ciphertext.score) && (ciphertext.score > (1.15*compare.score))){
				ciphertext.print_status();
				highest_score = ciphertext.score;
				best_key_length = key_length;
			}
		}
		
		ciphertext.key = ciphertext.key + int_to_char [0];
	}
	auto end = chrono::steady_clock::now();
	cout << "Elapsed cryptanalysis time : "<< chrono::duration_cast<chrono::seconds>(end - start).count()<< " s";
}

int main() {
	
	VigenereText ciphertext;
	cout << "Ciphertext: ";
	ciphertext.read_encrypted();
	
	vigenere_analysis(ciphertext);
	
	return 0;
}
