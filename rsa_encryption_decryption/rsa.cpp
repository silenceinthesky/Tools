//demo.cpp
// g++ demo.cpp -o demo -lcrypto
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
 
#include <iostream>
#include <string>
#include <cstring>
#include <cassert>
#include <vector>
#include "std_base64.h"

using namespace std;
RSA *createPrivateRSA(std::string key);
//加密
std::string EncodeRSAKeyFile( const std::string& strPemFileName, const std::string& strData )
{
	if (strPemFileName.empty() || strData.empty())
	{
		assert(false);
		return "";
	}
	FILE* hPubKeyFile = fopen(strPemFileName.c_str(), "rb");
	if( hPubKeyFile == NULL )
	{
		assert(false);
		return ""; 
	}
	std::string strRet;
	RSA* pRSAPublicKey = RSA_new();
	if(PEM_read_RSA_PUBKEY(hPubKeyFile, &pRSAPublicKey, 0, 0) == NULL)
	{
		assert(false);
		return "";
	}
 
	int nLen = RSA_size(pRSAPublicKey);
	char* pEncode = new char[nLen + 1];
	int ret = RSA_public_encrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pEncode, pRSAPublicKey, RSA_PKCS1_PADDING);
	if (ret >= 0)
	{
		strRet = std::string(pEncode, ret);
	}
	delete[] pEncode;
	RSA_free(pRSAPublicKey);
	fclose(hPubKeyFile);
	CRYPTO_cleanup_all_ex_data(); 
	return strRet;
}


    RSA *createPrivateRSA(std::string key) {
        RSA *rsa = NULL;
        const char *c_string = key.c_str();
        BIO *keybio = BIO_new_mem_buf((void *) c_string, -1);
        if (keybio == NULL) {
            return 0;
        }
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
        return rsa;
    }
 
//解密
std::string DecodeRSAKeyFile( const std::string& strPemFileName, const std::string& strData )
{
	if (strPemFileName.empty() || strData.empty())
	{
		assert(false);
		return "";
	}
	FILE* hPriKeyFile = fopen(strPemFileName.c_str(),"rb");
	if( hPriKeyFile == NULL )
	{
		assert(false);
		return "";
	}
	std::string strRet;

std::string strPkey = "-----BEGIN PRIVATE KEY-----\n"
"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDqBD26a0DhI2Q3\n"
"+fkEK12n8UT27QlTRwiukPQUfqXmMs1NNJHZEO3fBvQUZjqgS85NTEqFdeYqZ1Pp\n"
"7pyDScZUMjryzJiCEiQM2j/3yQethvdAwEHrblIYDjR+k0OU1FKQqGxMoeArvogm\n"
"y1xaOEn1jRaGuqLIrutP/JDysvEnZkzAJTvjxQEy34ITzCPpc0OaaRsqx5WHEq1b\n"
"g/mFpoAyvQmseSi0Vgn8ACULPlEQOajzkvTl/rHAcO4U6OvqeWAd8pp5RP2uXvIU\n"
"UjZejGpcp0sLgiyiUjLUAkQXzsnbMc4RONYJcy5zIZjB8QesSY+stJaSNDblY++n\n"
"dSMjuUeDAgMBAAECggEAXbJVBM7sqzgAaGktyv2SAiwX8MX3deB7GWnwUERlKEYu\n"
"7TqfKsocc6/VClXkI0o2z7w8GjOadF/quT9Qa0CeqBd0gsJoTav1wy+fbRaQfGoN\n"
"lV9lBV6mf/swCX3tESnx5PmKYyRtHRasbNv/nh/rfOWAn3EavD9M+Dmnz4TWCW+o\n"
"R8VEEltX0d53MF72PQBQRCwnu0DGQZnhWc6dyx8P/Loipr9B7QU0A/FGaBqulfX8\n"
"lxtkfNN6enKxLVf1T6tXZE8KTOHKRH6MtZ0gubFImUa1cJd5xXk/QgNGJVM0FDZQ\n"
"6YItp4AXqwvOOBa9vTGasZut1EVBhg9MBZ16zTmMAQKBgQD3njBCAPg2X0b30Q8n\n"
"zf375Hl9UK4HJK6jWwTNJnH4wTMlp9lwd1p9c8ouyrU+fBt8K+3R0DY6k3mtZN0b\n"
"i2VBLA7B3Wctk96fQxoA9PeHI2tPCUETibqlwUyB/yCFTfPOXX9omqLNFXDeUBqI\n"
"E9uAod1+MFExQ15nKxu87wNA1wKBgQDx8C+Nos5BBQR4og3HYrsVF2Az8g5NbLEf\n"
"WfDk8LgCzTmpoQPZhfd69b1aiAR7AGesBxlRDb6PZBiLTU2pRcjQHnie5H1uUzwY\n"
"3UyYd8RRozs3aScVsRHiqSnQr4kuUENBk7G1dJyQZhXx+jgAplQ5yB/XmjU6mH3d\n"
"MuQCgt+dNQKBgQDGuhE217pdQMgfGYyVQJBHOc17EmYo23rBJcpLr0AnCT84SGaN\n"
"CWz5ZBVuykb9l/MjC8p46iarijJMQ7fkZFJmJKrPUhZ9kMBJhzv2aqPBtF5p9x5g\n"
"RNgkMWdqqUv7UF2MUKNxWzGvcDa+ZQF2FqHCsaWmobZ31/6KxCEl15j/zwKBgHeq\n"
"9dp4zMwcTznb7jTRAPhNt6f58lkZigKX2i9jYaEBIaRloCHXwbFwG1jMLmsoqB7O\n"
"5BbTVY5XVEySz/cKLWnDqKXvHpuTUAZ8b4Z6twAqXP/rYwm3q8ERKz2tlYzy5lFp\n"
"XF0EcOx7kh8+RLUNkFuEQTvDatCw3JCsu1sCoNiBAoGBAOntB+eJxCloYN43pTin\n"
"VZPrHINz8SWIfTBtOfVG4DMZcLlHIrHmnN3KLPYe5IAYDnYAXjAqpqHnDpdV1rzz\n"
"tEwgIoPGh2NnLTOTUVu0US6LiojddjauLFsjwqrUcZcwMTAPNMlW/i3DSzm0IrX9\n"
"IUpw/rndwv0cIlb9C+mQg1FI\n"
"-----END PRIVATE KEY-----\n";
	//RSA* pRSAPriKey = RSA_new();
	RSA* pRSAPriKey = createPrivateRSA(strPkey);
        std::cout<<"11111111111"<<std::endl;
        std::cout<<"222:"<<std::endl;	
	//if(PEM_read_RSAPrivateKey(hPriKeyFile, &pRSAPriKey, 0, 0) == NULL)
	//{
	//	assert(false);
	//	return "";
	//}
	int nLen = RSA_size(pRSAPriKey);
	char* pDecode = new char[nLen+1];
 
	int ret = RSA_private_decrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pDecode, pRSAPriKey, RSA_PKCS1_PADDING);
	if(ret >= 0)
	{
		strRet = std::string((char*)pDecode, ret);
	}
	delete [] pDecode;
	RSA_free(pRSAPriKey);
	fclose(hPriKeyFile);
	CRYPTO_cleanup_all_ex_data(); 
	return strRet;
}
 
int main()
{
	// g++ rsa.cpp -o rsa.out -I/usr/include/openssl -L/usr/lib64/openssl -lssl -lcrypto
	// g++ -o rsa  rsa.cpp std_base64.cpp -lssl -lcrypto
        //原文
	const string one = "skl;dfhas;lkdfhslk;dfhsidfhoiehrfoishfsidf";
	cout << "one: " << one << endl;
 
	//密文（二进制数据）
	string two = EncodeRSAKeyFile("pubkey.pem", one);
	cout << "two: " << two << endl;

        string    str_data_ = "5Z/MYhzD3oOIueW/+asxM+wO5U2GJ+/lbGTn2MQ9HRGWIXOcDPVydX3D7TyZY49Zui+jRgo7qSI/iIeUs5Ok8/uiA7617OKzeQS7iI8L1o6O8SIab8xr+cjB0HA6DmGjYbbQ30qyJtntNvjfRCACEsrkXbM+K04zqXRndtKQRscjUogOuG7eQ/Iq1TkAPyadVRVeFfF7z1wsBB/WhuE2pXel8XI0gcrKQbv2zfY9BgqhYzoQvFusnVCaqIKMWP1GAO37GseIVboC3DBfPwgf5TAfe3h2fVQR9jUtwaaQsxSQnVI13FINcdLdTQmcEw2/JWQokRJfjk//CoWFAcWiKw==";
    // base64 decode
    int int_buff_len = str_data_.size() * 2;
    vector<unsigned char> vec_b64(int_buff_len, '\0');
    int int_result_len = 0;
    int ret = Stand_Base64::Decode(str_data_.c_str(), str_data_.size(), &vec_b64[0], int_buff_len, &int_result_len);
    if (0 != ret) {
    } else {
        str_data_ = std::string(vec_b64.begin(), vec_b64.begin() + int_result_len);
    }  


 
 
	//顺利的话，解密后的文字和原文是一致的
	string three = DecodeRSAKeyFile("prikey.pem", str_data_);
	cout << "three: " << three << endl;
	return 0;
}
