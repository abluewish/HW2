#include <iostream>
#include <string>
#include <fstream>
#include <crypto++/aes.h>
#include <crypto++/cryptlib.h>
#include <crypto++/rijndael.h>
#include <crypto++/modes.h>
#include <crypto++/files.h>
#include <crypto++/osrng.h>
#include <crypto++/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/default.h>
#include <sstream>

void usage(){
    std::cout<<"Syntax:"<< std::endl;
    std::cout<<"    To encrypt:  ./duke-crypter -e <input_file> <output_file>"<<std::endl;
    std::cout<<"    To decrypt:  ./duke-crypter -d <input_file> <output_file>"<<std::endl;
}

std::string encrypt(const std::string& plainText, CryptoPP::byte* iv, CryptoPP::byte* key, int key_length){
    std::string cipherText;
    
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption aesEncryptor(key, key_length, iv);
    CryptoPP::StringSource(plainText, true,
			new CryptoPP::StreamTransformationFilter(aesEncryptor,
					new CryptoPP::StringSink(cipherText)));
    
    std::cout<<cipherText.size()<<std::endl;
    return cipherText;
}

std::string decrypt(const std::string& cipherText, CryptoPP::byte* iv, CryptoPP::byte* key, int key_length){
    std::string plainText;
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption aesDecryptor(key, key_length, iv);
    CryptoPP::StringSource(cipherText, true,
            new CryptoPP::StreamTransformationFilter(aesDecryptor,
                    new CryptoPP::StringSink(plainText)));
    std::cout<<plainText.size()<<std::endl;
    return plainText;
}

void tobyte(std::string text, CryptoPP::SHA256 hash, CryptoPP::byte * key_byte){
    std::string digest;
    CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(std::cout));
    hash.Update((const CryptoPP::byte*)text.data(), text.size());
    digest.resize(hash.DigestSize()/2);
    hash.TruncatedFinal((CryptoPP::byte*)&digest[0], digest.size());
    //return CryptoPP::StringSource(digest,true, new CryptoPP::Redirector(encoder));
    
    //CryptoPP::byte key_byte[16];
    std::cout<<"keystr length = "<< digest.size()<<std::endl;
    for(int i=0;i<16;i++){
        key_byte[i] = digest[i];
    }
}

void printByte(CryptoPP::byte* bytes){
    std::string str(16, '.');
    for (int i = 0; i < 16; ++i) {
      str[i] = bytes[i];
    }
    std::string output;
    CryptoPP::StringSource sw(str, true,
                    new CryptoPP::HexEncoder(new CryptoPP::StringSink(output)) // HexEncoder
    );  
    std::cout<<output<<std::endl;
}

std::string getIv(std::string input_text){
    std::string iv(16,'.');
    for(int i=0;i<16;i++){
        iv[i]=input_text[i];
    }
    return iv;
}

int main(int argc, char* argv[]){
    if(argc<4){
        usage();
        return 1;
    }

    std::string op(argv[1]);
    
    std::ifstream input_file(argv[2]);
    std::ofstream output_file(argv[3]);
    //std::string line;
    CryptoPP::SHA256 hash;
    CryptoPP::AutoSeededRandomPool rnd;

    std::string key;
    
    std::cout << "Please enter a secret key:" << std::endl;
    std::cin >> key;
    //CryptoPP::byte* key_byte;
    CryptoPP::byte * key_byte = new CryptoPP::byte[16];
    try{
        tobyte(key,hash,key_byte);
    }catch(std::exception e){
        std::cout<< "the key length," << key.size()<<"is not allowed";
        return 1;
    }

    std::cout<< "key is ";
    printByte(key_byte);


    if(op == "-e"){
        CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
        std::cout<<"block size is "<<CryptoPP::AES::BLOCKSIZE<<std::endl;
        rnd.GenerateBlock(iv, sizeof(iv));
        std::string iv_str(16, '.');
        for(int i=0;i<16;i++){
            iv_str[i]=iv[i];
        }
        std::cout<< "iv is ";
        printByte(iv);

        std::ostringstream buf;
        buf.str("");
        std::string line;
        while(getline(input_file,line)){
            buf << line;
        }
        std::string input_text = buf.str();
        try{
            std::string cypher_text=encrypt(input_text,iv,key_byte,16);
            CryptoPP::byte cypherBytes[16];
            for(int i=0;i<16;i++){
                cypherBytes[i] = cypher_text[i];
            }
            std::string plainHash;
            hash.Update((const CryptoPP::byte*) input_text.data(),input_text.size());
            plainHash.resize(hash.DigestSize()/2);
            hash.TruncatedFinal((CryptoPP::byte*)&plainHash[0],plainHash.size());
            
            CryptoPP::byte hashBytes[16];
            for(int i=0;i<16;i++){
                hashBytes[i]=plainHash[i];
            }
            output_file<<iv_str;
            output_file<<cypher_text;
            output_file<<plainHash;
            input_file.close();
            output_file.close();
        }catch(const CryptoPP::Exception &e){
            std::cerr<<e.what() << std::endl;
            return 1;
        }
    }else if(op == "-d"){
        
        std::ostringstream buf;
        buf.str("");
        std::string line;
        while(getline(input_file,line)){
            buf << line;
        }
        std::string input_text = buf.str();

        std::string iv_str = getIv(input_text);
        CryptoPP::byte iv[16];
        for(int i=0;i<16;i++){
            iv[i]=iv_str[i];
        }

        std::string cypher_text(input_text.size()-32,'.');
        for(int i=16;i<input_text.size()-16;i++){
            cypher_text[i-16]=input_text[i];
        }

        output_file<<decrypt(cypher_text,iv,key_byte,16);

        input_file.close();
        output_file.close();
        
    }else{
        usage();
        return 1;
    }
    free(key_byte);

    return 0;
}