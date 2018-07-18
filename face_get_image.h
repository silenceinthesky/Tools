#ifndef FACE_GET_IMAGE_
#define FACE_GET_IMAGE_
#include "ZXBase.h"
#include "sm_comm.h"
using namespace com::cft::pf::comm;

class CFaceGetImage: public ZXBase {
public:
    CFaceGetImage();
	virtual ~CFaceGetImage();

private:
	void GetParams();
	int GetCardImages();
	
	// 从冷备接口获取照片
	int FeatchImageFromColdBackUp();
	bool CanGetImage(long dwBusinessId);
	int IsColdBackUp(string filename);
	bool CheckImageFileName(const std::string& filename);
	int CurlMethodWithGet(const std::string &str_ip, int port,
                                 	  const std::string &strParams, const std::vector<std::string>&headerVet,
                                      std::string &rsp_str);
	int CurlMethodWithGet(const std::string &str_ip, int port,
                                 	  const std::string &strParams,
                                      std::string &rsp_str);	
	int GetFileFromTcsfs(int iModid, int iCmdid,const string &strIp, int iPort, \
							int iTimeOut,int dwSeqnum,const string &strEntNo,const string &strSeqNo,const string &strTcfName, string &strFileData);
	void Execute();
		
private:
	string m_strAccount;
	int m_dwSeqNum;
	long long int m_ddwBusinessId;
	long long int m_ddwTransactionId;
	long long int m_ddwAuthTime;
	string m_strImageName;
	string m_strErrMsg;
	int m_iResult;
	string m_strImageData;
	string m_strName;
    string m_strId;
	string m_strTfcsIp;
	int m_iTfcsPort;
	int m_iTfcsTimeOut;
	int m_iTfcsModid;
	int m_iTfcsCmdid;
	string m_strEncFlag;                              // 标识冷备接口返回数据是否为AES加密 
};
#endif
