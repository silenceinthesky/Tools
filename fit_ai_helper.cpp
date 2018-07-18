#include "fit_ai_helper.h"
#include <time.h>
#include <string>
#include <vector>


using std::string;
using std::vector;
using std::cout;
using std::endl;

namespace Fit_AI_Tools {

// g++ -o xiao ./fit_ai_helper.cpp  -I/usr/local/openssl-1.0.1h/include/ -L/usr/local/openssl-1.0.1h/lib/ -lcrypto

// 生成len长度的随机字符串,目前使用12位或者16位长度
std::string GenerateStr(int len) {
    std::vector<char> vec_res;
    vec_res.resize(len, '\0');
    int i=0;
    srand(time(NULL));//通过时间函数设置随机数种子，使得每次运行结果随机。
    for(; i < len; i++) {
        vec_res[i] = rand() % 256;
    }
    return string(vec_res.begin(), vec_res.begin() + len);
}


/**
 * aes gcm 明文加密函数
 * params plaintext  明文
 * params key        密钥
 * params iv         初始化向量
 * return            加密后的密文
 */
std::string aes_128_gcm_encrypt(const std::string& plaintext, 
                                const std::string& key, 
                                const std::string& iv) {
    std::string str_res;
    size_t enc_length = plaintext.size()*3;
    std::vector<unsigned char> output;
    output.resize(enc_length,'\0');

    int actual_size=0, final_size=0;
    EVP_CIPHER_CTX* e_ctx = EVP_CIPHER_CTX_new();

    //加载密钥，初始化向量iv
    EVP_EncryptInit(e_ctx, EVP_aes_128_gcm(), (const unsigned char*)(key.c_str()), (const unsigned char*)(iv.c_str()));
    
    EVP_EncryptUpdate(e_ctx, &output[0], &actual_size, (const unsigned char*)plaintext.data(), plaintext.length() );

    EVP_EncryptFinal(e_ctx, &output[0+actual_size], &final_size);
    
    EVP_CIPHER_CTX_ctrl(e_ctx, EVP_CTRL_GCM_GET_TAG, 16, &output[0+actual_size]);

    EVP_CIPHER_CTX_free(e_ctx);

    for (unsigned int i=0; i<output.size(); i++) {
        if( output[i] != '\0') {
            str_res += output[i];
        } else {
            break;
        }
    }
    return str_res;
}

/**
 * aes gcm 密文解密函数
 * params ciphertext 密文
 * params key        密钥
 * params iv         初始化向量
 * return            解密后的明文
 */
std::string aes_128_gcm_decrypt(const string& ciphertext, 
                                std::string& key, 
                                const std::string& iv){
    std::vector<unsigned char> plaintext;
    plaintext.resize(ciphertext.size(), '\0');
    unsigned char tag[AES_BLOCK_SIZE];
    int actual_size=0, final_size=0;
    EVP_CIPHER_CTX *d_ctx = EVP_CIPHER_CTX_new();
    
    EVP_DecryptInit(d_ctx, EVP_aes_128_gcm(), (const unsigned char*)key.c_str(), (const unsigned char*)(iv.c_str()));
    
    EVP_DecryptUpdate(d_ctx, &plaintext[0], &actual_size, (const unsigned char*)(&ciphertext[0]), ciphertext.size() - AES_BLOCK_SIZE);

    EVP_CIPHER_CTX_ctrl(d_ctx, EVP_CTRL_GCM_SET_TAG, AES_BLOCK_SIZE, tag);

    EVP_DecryptFinal(d_ctx, &plaintext[actual_size], &final_size);

    EVP_CIPHER_CTX_free(d_ctx);

    plaintext.resize(actual_size + final_size, '\0');

    return std::string(plaintext.begin(),plaintext.end());
}

//单个字符转十六进制
std::string CharToHex(const char & c) {
      string result;
      char first, second;

      first = (c & 0xF0) / 16;
      first += first > 9 ? 'A' - 10 : '0';
      second = c & 0x0F;
      second += second > 9 ? 'A' - 10 : '0';

      result.append(1, first);
      result.append(1, second);
      return result;
}

//字符串转十六进制
 std::string StrToHex(const std::string & str) {
      std::string result;
      for(unsigned index=0;index<str.size();index++) {
        result+= CharToHex(str[index]);
      }      
      return result;    
}


std::string sha256(const std::string& str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex<<(int)hash[i];
    }
    return ss.str();
}

std::string HmacSha256(const std::string& key, const std::string& input) {
        const EVP_MD * engine = EVP_sha256();
        vector<unsigned char> vec_res;
        vec_res.resize(EVP_MAX_MD_SIZE, '\0');

        unsigned int output_length = 0;
        
        HMAC_CTX ctx;
        HMAC_CTX_init(&ctx);
        HMAC_Init_ex(&ctx, key.c_str(), key.size(), engine, NULL);
        HMAC_Update(&ctx, (unsigned char*)input.c_str(), input.size());        // input is OK; &input is WRONG !!!

        HMAC_Final(&ctx, &vec_res[0], &output_length);
        HMAC_CTX_cleanup(&ctx);

        return string(vec_res.begin(), vec_res.begin() + output_length);
}


} //namespace end Fit_AI_Tools 
 
int main(int argc, char **argv) {
    //g++ aes_gcm.cpp -lssl

    unsigned char key[16] = {
        0x3b, 0x81, 0xfb, 0x74,
        0x94, 0x5e, 0xd0, 0x9e,
        0x30, 0x24, 0x84, 0x5c,
        0x87, 0x3e, 0xed, 0x9f,
    }; 

    std::string key_use = std::string((char*)key, 16);
    std::cout<<"key_use:"<<key_use<<endl;

     unsigned char iv[12] = {
     0xbb, 0xde, 0x3c, 0xa4, 
     0x48, 0x78, 0x4f, 0xa8,
     0x6a, 0xe9, 0xf7, 0xc4,
     };

     std::string iv_use = std::string((char*)iv, 12);
     std::cout<<"iv_use:"<<iv_use<<endl;

    //text to encrypt
    std::string plaintext= "320722197910180016xi小气";
    std::cout << "plaintext:"<< plaintext << endl;
 
    //encrypt
    std::string str_des = Fit_AI_Tools::aes_128_gcm_encrypt(plaintext, key_use, iv_use);
    std::cout<<"after encrypt, str_des="<< str_des << std::endl;
    std::string str_des_hex = Fit_AI_Tools::StrToHex(str_des);
    std::cout<<"str_des to hex:"<<str_des_hex<<endl;

    //std::string aes_128_gcm_decrypt(std::vector<unsigned char> ciphertext, std::string key)
    vector<unsigned char> data(str_des.begin(), str_des.end());
    std::string str_des_res = Fit_AI_Tools::aes_128_gcm_decrypt(str_des, key_use, iv_use);
    cout<<"str_des_res:"<<str_des_res<<endl;

    std::string str_before_sha256 = "appid=Lfp0iILmY0GG9aaMdM36NkWOGNmdyIDB&nonce=2e081c973e4ac90a2b347214&idcard_name=HfsfpxpeEmig4cRXWFOix4sYAfJeABLyHQ==&idcard_number=yFShdr7cxtcMCv0p+gKBwN1YzwY/hYaEBJx476RXT1rjdQ==&timestamp=1523282075";
    std::string str_a_sha = Fit_AI_Tools::sha256(str_before_sha256);
    std::cout<<"str_a_sha="<<str_a_sha<<endl;
    
    string str_hmac = Fit_AI_Tools::HmacSha256("123",str_before_sha256);
    std::cout<<"str_hmac_sha256:"<<Fit_AI_Tools::StrToHex(str_hmac)<<endl;
    
    return 0;
}
