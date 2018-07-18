#ifndef FIT_AI_HELPER_H
#define FIT_AI_HELPER_H
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>




#include <string>
#include <sstream>
#include <vector>
#include <iostream>
#include <iomanip>
#include <sstream>

namespace Fit_AI_Tools {

std::string GenerateStr(int len);

std::string aes_128_gcm_decrypt(std::vector<unsigned char> ciphertext, std::string& key, const std::string& iv);
std::string aes_128_gcm_encrypt(const std::string& plaintext, const std::string& key, const std::string& iv); 

std::string CharToHex(const char & c);
std::string StrToHex(const std::string & str);

std::string sha256(const std::string& str);

std::string HmacSha256(const std::string& key, const std::string& input);


};

#endif