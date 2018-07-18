#include "face_get_image.h"
#include "CTools.h"
#include <curl/curl.h>
#include "RuntimeGather.h"
#include "Aes_Helper.h"
#include "facecheck_gab_system_error_code.h"
#include "qos_client.h"
#include "std_base64.h"
#include "sm_comm.h"
#include "CResData.h"
#include "string_utils.h"
#include "transxmlcfg.h" 
#include "ckv_client.h"
#include "urlcodec.h"
#include "sm_object.h"
#include "tcsfs_all_helper.h"
#include "std_base64.h"
#include "comm/md5.h"



using namespace tenpay::credit;
using namespace CFT::PayComm;
using namespace com::cft::pf::comm;

const string kColdBackUpConf = "cold_backup_new";
const string kColdBackUpURL = "/router?appkey=txzx&method=txzx.rop.hdfs.standby&v=1.0&format=json&sign=7CB323A6E37E2599B75DD5A7C6B666EE";
const int kMaxBuff = 1024 * 1024 * 32;

static AES_KEY aes_key;


class CImageEntNo {
public:
	bool bInit;
	bool bSwitch;
	set<long> entNoSet;
	
public:
	CImageEntNo() {
		bInit = false;
		bSwitch = false;
		entNoSet.clear();
	}
};
	
static CImageEntNo g_ImageEntNo;
DECLARE_FASTCGI(CFaceGetImage)


static std::map<std::string, CURL *> g_addrCurlMap;

class CurlGlobalInit {
public:
    CurlGlobalInit() {
        curl_global_init(CURL_GLOBAL_ALL);
    }

    ~CurlGlobalInit() {
        std::map<std::string, CURL *>::iterator iter = g_addrCurlMap.begin();
        for (; iter != g_addrCurlMap.end(); ++iter) {
            curl_easy_cleanup(iter->second);
            iter->second = NULL;
        }
    }
};

static int writer(char *data, size_t size, size_t nmemb, std::string *writerData) {
     int len = size*nmemb;
     writerData->append(data, len);
     return len;
}


static char* md5_buf(u_char* buf,int size) {
	static u_char p[16];
    MD5_CTX md5;
    MD5Init(&md5);
    MD5Update(&md5,(u_char*)buf,size);
    MD5Final(&md5,p);
	return (char*)p;
}


static char* md5_str(u_char* buf,int size) {
	int i;
	u_char *p;
	u_char *q;
	static char tmp[36];
	p = (u_char*)md5_buf(buf,size);
	q = (u_char*)tmp;
	for(i = 0 ; i < 16 ; i++,q+=2)
		snprintf((char*)q,3,"%02x",p[i]);
	return tmp;
}

static void str_to_hex(const char pwd[33], char key[17]) {
	char* tmp = new char[33];
	memset(tmp, 0, 33);
	strncpy(tmp, pwd, 32);
	
	int d = 0;
	for(int i=15; i>=0; i--)
	{
			tmp[i*2+3]=0;
			sscanf(tmp+i*2, "%02x", &d);
			key[i] = (char)d;
	}
	delete [] tmp;
}

static int decode(const char *src, char *dst, int len, const char* key) {
	if(AES_set_decrypt_key((const unsigned char *)key, AES_BLOCK_SIZE * 8, &aes_key)<0)
	{
		return -3001;
	}
    
	unsigned char iv[AES_BLOCK_SIZE];	//加密的初始化向量
    memset(iv, 0, AES_BLOCK_SIZE);      //iv一般设置为全0,可以设置其他，但是加密解密要一样就行		

	AES_cbc_encrypt((const unsigned char*)src, (unsigned char*)dst, len, &aes_key, iv, AES_DECRYPT);
	return 0;
}


static int aes_decode(const char *src,char *dst,int slen,const char key[33])
{
	char bkey[17] = {0};
	str_to_hex(key,bkey);
	return decode(src,dst,slen,bkey); 
}


CFaceGetImage::CFaceGetImage():
	m_strAccount(""), m_dwSeqNum(0),  m_ddwBusinessId(0), 
	m_ddwTransactionId(0), m_ddwAuthTime(0),
	m_strImageName(""), m_strErrMsg(""), m_iResult(0), 
	m_strImageData(""), m_strName(""), m_strId(""),
	m_strTfcsIp(""), m_iTfcsPort(0), m_iTfcsTimeOut(0),
	m_iTfcsModid(0), m_iTfcsCmdid(0), m_strEncFlag("") {	
	this->outPutType = OUTPUTXML;
	this->subModule = "zx_sm_ocr";
	m_dwSeqNum = SM_COMM::GetPidNum();
}

CFaceGetImage::~CFaceGetImage() {
}



//没有头部信息需要补充
int CFaceGetImage::CurlMethodWithGet(const std::string &str_ip, int port,
                                 	  const std::string &strParams,
                                      std::string &rsp_str) {
	std::vector<std::string> header_vet;
	header_vet.clear();
	return CurlMethodWithGet(str_ip, port, strParams, header_vet, rsp_str);
}

/**
 * 封装HTTP GET 请求
 *  headerVet: 请求头部信息
 *  rsp_str: HTTP 响应body
 */
int CFaceGetImage::CurlMethodWithGet(const std::string &str_ip, int port,
                                 	  const std::string &strParams, const std::vector<std::string>&headerVet,
                                      std::string &rsp_str) {
    rsp_str.clear();
	CURLcode res_code;
	CURL *curl = NULL;

	std::stringstream ip_port_key;
    ip_port_key << str_ip << ":" << port;
    std::map<std::string, CURL *>::iterator iter = g_addrCurlMap.find(ip_port_key.str());

    if (iter != g_addrCurlMap.end()) {
        curl = iter->second;
    } else {
        curl = curl_easy_init();
    }
	
	std::string str_url = std::string("http://") + ip_port_key.str() + strParams;

	if (curl) {
		DebugLog("CFaceGetImage::CurlMethodWithGet, addr:%s", str_url.c_str());
		curl_easy_setopt(curl, CURLOPT_URL, str_url.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writer);  
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rsp_str);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, m_iTfcsTimeOut);
		curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
		curl_easy_setopt(curl, CURLOPT_PORT, port);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60);
		curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);  
		curl_easy_setopt(curl, CURLOPT_TCP_KEEPIDLE, 120L);   
		curl_easy_setopt(curl, CURLOPT_TCP_KEEPINTVL, 60L);
		g_addrCurlMap[ip_port_key.str()] = curl;
	}
	else {
		m_strErrMsg = "系统繁忙，请稍后再试。";
		return ST_FACE_ERRCODE_SYSTEM;
	}	
	if (!headerVet.empty()) {
		struct curl_slist *headers = NULL; 
		std::vector<std::string>::const_iterator iter = headerVet.begin();
		for (; iter != headerVet.end(); ++iter) {
			headers = curl_slist_append(headers, iter->c_str());
		}
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	}
	res_code = curl_easy_perform(curl);
    if (CURLE_OK != res_code) {
		ErrorLog("CFaceGetImage::CurlMethodWithGet, curl_easy_perform error.ret_code:%d, url:%s", res_code, str_url.c_str());
		m_strErrMsg = "系统繁忙，请稍后再试。";
        return ST_FACE_ERRCODE_SYSTEM;
    }
	DebugLog("CFaceGetImage::CurlMethodWithGet, url:%s, res.size:%d", str_url.c_str(), rsp_str.size());
    long http_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200) {
		ErrorLog("CFaceGetImage::CurlMethodWithGett, CURLINFO_RESPONSE_CODE error.http_code:%d,url:%s",http_code,str_url.c_str());
		m_strErrMsg = "系统繁忙，请稍后再试。";
		return ST_FACE_ERRCODE_SYSTEM;
    }
    return 0;
}

int CFaceGetImage::GetFileFromTcsfs(int iModid, int iCmdid,const string &strIp, int iPort, \
										int iTimeOut,int dwSeqnum,const string &strEntNo,const string &strSeqNo,const string &strTcfName, string &strFileData) {
	stringstream ossUrl;
	ossUrl << "http://" << strIp << ":" << iPort << "/file_api";
	string strUrl = ossUrl.str();
	FsMsg reqMsg;
	FsMsgHelper::get_FileGetReq(
					reqMsg,
					dwSeqnum,
					strEntNo,
					strSeqNo,
					strTcfName);
	vector<char> buf;
	buf.reserve(BUF_SIZE);
	int len = FsMsgHelper::pack_msg(reqMsg, &buf[0], BUF_SIZE);

	vector<std::string> vecHeader;
	vecHeader.push_back("Expect:");

	string strResponse;
	int ret = SM_COMM::CurlPerform(strUrl,iModid,iCmdid,strIp,iPort,iTimeOut,&buf[0],len,vecHeader,strResponse);
	if(ret != 0)
	{
		ErrorLog("SM_COMM::GetFileFromTcsf, CurlPerform failed.ret:%d,url:%s",ret,strUrl.c_str());
		m_strErrMsg = "系统繁忙，请稍后再试。";
		return ret;
	}
	FsMsg respMsg;
	int retCode = 0;
	string retMsg  = "";
	FsMsgHelper::unpack_msg(strResponse.c_str(),strResponse.size(), respMsg);
	FileGetRsp *rsp = respMsg.mutable_filegetrsp_body();
	retCode =rsp->ret_code();
	retMsg = rsp->ret_msg();
	if (retCode != 0) {
		InfoLog("CFTRspHelper::get_FileGetReq failed.retcode:%d,retMsg:%s,http:%s,file:%s",retCode,retMsg.c_str(),strUrl.c_str(),strTcfName.c_str());
		m_strErrMsg = "线上查询，文件不存在。";
		return retCode;
	}
	
	strFileData = rsp->contents();
	DebugLog("CFaceGetImage::GetFileFromTcsfs:url:%s,data_size:%d,name:%s",strUrl.c_str(),strFileData.size(),strTcfName.c_str());
	return 0;
}


void CFaceGetImage::GetParams() {
	/**
	  * 出错返回信息格式设置,默认为XML;
	  * 当url中包含flag字段，且值为1时，若获取图片出错，返回信息格式为json；
	  * 没有flag字段或者flag的值不为1，则出错返回信息保持为xml格式（微信和kf）；
	*/
	string str_flag = reqData.GetPara("flag");
	if (!str_flag.empty() && str_flag == "1") {
		InfoLog("response format transform to json.");
		this->resData.SetOutPutType(OUTPUTJSON);
	}

	string strBusinessId = reqData.GetPara("ent_no");
	m_ddwBusinessId = StringUtils::str2int64(strBusinessId);

	//商户号限制，开关控制是否开启，并设置能够拉照片的商户号名单
	if (!CanGetImage(m_ddwBusinessId)) {
		ErrorLog("商户号：%lld不在能够拉取照片的名单之中.", m_ddwBusinessId);
		throw CTrsExp(ST_FACE_ERRCODE_AUTH, "没有权限访问照片。");
	}
	
	CZxCacheOp *pZxCacheOp = CZxCacheOp::GetInstance();
    if (0 != pZxCacheOp->Initialize(&g_allVar, this->subModule)) {
        throw CTrsExp(AppError::ERR_SYSTEM_EXCEPTION, "Cache system op interface init failed.");
    }

	//获取商户号密钥
	string strDataKey = "";
	m_iResult = pZxCacheOp->GetAuthKey(strBusinessId,strDataKey);
	if (m_iResult != 0) {
		m_strErrMsg = "授权有误.";
		m_iResult = ST_FACE_ERRCODE_AUTH;
		ErrorLog("GetAuthKey error. business_id:%s, ret:%d", strBusinessId.c_str(), m_iResult);
		throw CTrsExp(m_iResult,m_strErrMsg);
	}
	string strData = reqData.GetPara("req_data");
	KVMap reqMap;
	InfoLog("CFaceGetImage::GetParams, req_data:%s, business_key:%s",strData.c_str(),strDataKey.c_str());
	if (strDataKey.empty()) {
		m_strErrMsg = "商户号对应的商户密钥为空.";
		throw CTrsExp(ST_FACE_ERRCODE_PARAM, m_strErrMsg);
	}

	//使用密钥解析req_data字段
	m_iResult = SM_COMM::GetReqData(strData, strDataKey, reqMap);
	m_strAccount = reqMap.GetStringValue("uin","");
	m_strImageName = reqMap.GetStringValue("image_fn",""); 
	
	m_ddwTransactionId = StringUtils::str2int64(reqData.GetPara("seq_no"));
	InfoLog("CFaceGetImage::GetParams, ent_no:%lld, uin:%s, seq_no:%lld, image_fn:%s", \
			m_ddwBusinessId, m_strAccount.c_str(), m_ddwTransactionId, m_strImageName.c_str());
	if ((m_ddwBusinessId == 0) || m_strImageName.empty() || (m_ddwTransactionId == 0) || m_strAccount.empty()) {
		m_strErrMsg = "参数错误：商户号, 账号, 文件名, 流水号不能为空。";
		throw CTrsExp(ST_FACE_ERRCODE_PARAM, m_strErrMsg);
	}

	if(!CheckImageFileName(m_strImageName)) {
		ErrorLog("CheckImageFileName, file_name:%s", m_strImageName.c_str());
		m_strErrMsg = "文件名格式有误。";
		throw CTrsExp(ST_FACE_ERRCODE_PARAM, m_strErrMsg);
	}
	
	m_ddwAuthTime = SM_COMM::GetAuthTime(m_ddwTransactionId); //获得流水号的申请时间，为时间戳
}


/**
  * 返回false表示没有该商户号没有权限获取照片，返回true才表示程序可以继续往下执行
  * switch置1，表示对商户号进行限制，其他值则表示不检查商户号
*/
bool CFaceGetImage::CanGetImage(long dwBusinessId) {
	DebugLog("CFaceGetImage::CanGetImage, g_ImageEntNo.bSwitch:%d, g_ImageEntNo.entNoSet.size():%d", \
			g_ImageEntNo.bSwitch,g_ImageEntNo.entNoSet.size());
	string strItemName = "ent_no_check";
	if(!g_ImageEntNo.bInit) {
		g_ImageEntNo.bInit = true;
		if (g_allVar.GetValue(strItemName.c_str(), "switch") == "1") {
			g_ImageEntNo.bSwitch = true;
		}
		else {
			g_ImageEntNo.bSwitch = false;
		}
		g_ImageEntNo.entNoSet.clear();
		string strData = g_allVar.GetValue(strItemName.c_str(), "ent_no");
		if(!strData.empty()) {
			DebugLog("CFaceGetImage::CanGetImage, ent_no:%s",strData.c_str());
			vector<string> strVec;
			Tools::StrToVector(strVec, strData, "|");
			vector<string>::const_iterator iter = strVec.begin();
			for (; iter != strVec.end(); iter++) {
				if (iter->size() != 0) {
					DebugLog("add:%s",iter->c_str());
					g_ImageEntNo.entNoSet.insert(StringUtils::str2int64(*iter));
				}
			}
		}
	}
	
	if (!g_ImageEntNo.bSwitch) {
		return true;
	}
	if (g_ImageEntNo.entNoSet.find(dwBusinessId) != g_ImageEntNo.entNoSet.end()) {
		return true;
	}
	return false;
}

/**
  *@Param:filename  照片文件名
  *返回0表示照片已经冷备,1表示正常，-1表示异常
 */
int CFaceGetImage::IsColdBackUp(string filename) {
	vector<string> strVec;
	Tools::StrToVector(strVec, filename, "-");
	if (strVec.size() < 3) {
		return -1;
	}
	int file_date = StringUtils::str2int64(strVec[2]) + 201601;
	InfoLog("CFaceGetImage::IsColdBackUp, file_date:%d", file_date);
	if (file_date < StringUtils::str2int64(g_allVar.GetValue("number_conf", "cold_backup_date"))) {
		return 0;
	}
	return 1;
}

//return false if filename is not valid
bool CFaceGetImage::CheckImageFileName(const std::string& filename) {
	string::size_type pos = filename.find("."); //如果没有找到，则pos为size_t所能表示的最大值
	string file_name = filename.substr(0, pos);
	for (string::size_type i = 0; i<file_name.size();i++) {
		if (!isdigit(filename[i]) && file_name[i] != '-') {
			return false;
		}
	}
	return true;
}


//根据文件名，去线上拉取照片
int CFaceGetImage::GetCardImages() {
	InfoLog("Begin exec GetCardImages online.");
	SM_COMM::GetFaceItemArguments("ftcs", m_iTfcsTimeOut, m_strTfcsIp, m_iTfcsPort, m_iTfcsModid, m_iTfcsCmdid);
	m_dwSeqNum ++;
	int iRet = GetFileFromTcsfs(m_iTfcsModid, m_iTfcsCmdid, m_strTfcsIp, m_iTfcsPort, m_iTfcsTimeOut, \
			m_dwSeqNum, StringUtils::int2str(m_ddwTransactionId), StringUtils::int2str(m_ddwBusinessId), m_strImageName, m_strImageData);
	if (iRet != 0) {
		m_iResult = SM_COMM::GetErrMsgForErrCode(iRet, ST_FACE_ERRCODE_TIMEOUT, "系统繁忙，请稍后再试。", m_strErrMsg);
		return m_iResult;
	}
	
	DebugLog("GetCardImages online, m_strImageData.size():%d", m_strImageData.size());
	return 0;	
}





int CFaceGetImage::FeatchImageFromColdBackUp() {
	InfoLog("Begin exec FeatchImageFromColdBackUp.");
	string str_rsp_coldback;
	SM_COMM::GetFaceItemArguments(kColdBackUpConf, m_iTfcsTimeOut, m_strTfcsIp, m_iTfcsPort, m_iTfcsModid, m_iTfcsCmdid);
	string str_uri = string(kColdBackUpURL) + string("&") + string("filename=") + m_strImageName;
	int i_ret = CurlMethodWithGet(m_strTfcsIp, m_iTfcsPort, str_uri, str_rsp_coldback);
	if (0 != i_ret) {
		ErrorLog("FeatchImageFromColdBackUp, CurlMethodWithGet failed, ret:%d", i_ret);
		m_iResult = SM_COMM::GetErrMsgForErrCode(i_ret, ST_FACE_ERRCODE_TIMEOUT, "系统繁忙，请稍后再试。", m_strErrMsg);
		return m_iResult;
	}

    // 返回json格式数据包进行解析
    Json::Reader json_reader;
    Json::Value json_content;            

    if (!json_reader.parse(str_rsp_coldback.c_str(), json_content, false)) {
        ErrorLog("FeatchImageFromColdBackUp, json from coldback's rsp parse failed.");
        return -1;
    }

	if (json_content["retcode"].isInt()) {
		m_iResult = json_content["retcode"].asInt();
		if (0 != m_iResult) {
			return -1;
		}
	} else {
		ErrorLog("FeatchImageFromColdBackUp exception, no retcode return in rsp.");
		return -1;
	}

    if (json_content["flag"].isString()) {
		m_strEncFlag = json_content["flag"].asString();
    }

	DebugLog("Get rsp from coldback, retcode:%d, flag:%s", m_iResult, m_strEncFlag.c_str());

	// 加密
	if ("1" == m_strEncFlag) {
		string str_enc_img_data = json_content["data"].asString();
		DebugLog("flag=1, str_enc_img_data.size:%d", str_enc_img_data.size());

		//将图片数据进行base64解码
	    vector<unsigned char>  vec_b64;
	    int int_buff_len = str_enc_img_data.size() * 2;
	    vec_b64.resize(int_buff_len, '\0');
	    int int_result_len = 0;
	    int ret = Stand_Base64::Decode(str_enc_img_data.c_str(), str_enc_img_data.size(), &vec_b64[0], int_buff_len, &int_result_len);
	    if (0 != ret) {
	        ErrorLog(" Execute Decode image failed. Image size: %d",
	         str_enc_img_data.size());
	    } else {
	        str_enc_img_data = std::string(vec_b64.begin(), vec_b64.begin() + int_result_len);
	    }
			

		int pos = m_strImageName.rfind("-");
		string str_key =  m_strImageName.substr(m_strImageName.rfind("-", pos-1) + 1);
		DebugLog("image_data enc, file_name:%s, str_key:%s", m_strImageName.c_str(), str_key.c_str());
		char* e_key = md5_str((u_char *)str_key.c_str(), str_key.size());

		char bkey[17] = {0};
		str_to_hex(e_key, bkey);
		vector<char> vec_res;
		vec_res.resize(kMaxBuff, '\0');
		if (aes_decode(str_enc_img_data.c_str(), &vec_res[0], str_enc_img_data.size(), e_key) != 0) {
			DebugLog("aes_decode failed.");
			return -2;
		}
		m_strImageData = string(vec_res.begin(), vec_res.begin() + str_enc_img_data.size());

	} else {

		m_strImageData = json_content["data"].asString();
		DebugLog("flag=0, m_strImageData.size:%d", m_strImageData.size());

		//将图片数据进行base64解码
	    vector<unsigned char>  vec_res;
	    int int_buff_len = m_strImageData.size() * 2;
	    vec_res.resize(int_buff_len, '\0');
	    int int_result_len = 0;
	    int ret = Stand_Base64::Decode(m_strImageData.c_str(), m_strImageData.size(), &vec_res[0], int_buff_len, &int_result_len);
	    if (0 != ret) {
	        ErrorLog(" Execute Decode image failed. Image size: %d",
	         m_strImageData.size());
	    } else {
	        m_strImageData = std::string(vec_res.begin(), vec_res.begin() + int_result_len);
	    }
				
	}
	
	DebugLog("FeatchImageFromColdBackUp, m_strImageData.size:%d", m_strImageData.size());
	return 0;
}


void CFaceGetImage::Execute() {
    string strConfPath = g_allVar.GetSubModule(this->subModule);
    m_pZXManager = ZXManager::GetInstance();
    m_pZXManager->Init(strConfPath);

	GetParams();

	/**
	  * 通过文件名判断文件是否已经冷备
 	  * 如果已经冷备，去调用冷备接口
	*/
	int i_ret = IsColdBackUp(m_strImageName);
	if (0 == i_ret) {                             //先查冷备
		i_ret = FeatchImageFromColdBackUp();
		if (0 != i_ret) {                         //冷备查询失败，查线上
			InfoLog("Query ColdBackUp failed!");
			i_ret = GetCardImages();
			if (0 != i_ret) {
				m_strErrMsg = "照片查询失败.";
				ErrorLog("先后查询冷备、线上皆失败。");
				throw CTrsExp(i_ret, m_strErrMsg); 
			}
		}
	} 
	else if (1 == i_ret) {                        //先查线上
		i_ret = GetCardImages();
		if (0 != i_ret) {
			InfoLog("Query Online failed!");
			i_ret = FeatchImageFromColdBackUp();
			if (0 != i_ret) {                     //冷备查询失败，查线上
				m_strErrMsg = "照片查询失败。";
				ErrorLog("先后查询线上、冷备失败。");
				throw CTrsExp(i_ret, m_strErrMsg);
			}
		}
	}
	else {
		ErrorLog("IsColdBackUp, file_name:%s", m_strImageName.c_str());
		m_iResult = ST_FACE_ERRCODE_PARAM;
		m_strErrMsg = "文件名格式有误.";
		throw CTrsExp(m_iResult,m_strErrMsg);
	}
	
	
	resData.SetOutPutType(NOTOUTPUT);
	cgicc::FCgiIO* m_pOut = resData.GetOutPut();
	//DebugLog("m_strImageData:%s", m_strImageData.c_str());
	//*m_pOut << "Content-Disposition: attachment; filename=" << m_strImageName << endl;
    *m_pOut << "Content-Length:" << m_strImageData.size() << endl;
    *m_pOut << "Content-type: image/jpg \r\n\r\n";
    *m_pOut << m_strImageData << endl;
	return;
}





