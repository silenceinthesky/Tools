#include "face_recognition_fit_ai.h"
#include "sm_comm.h"
#include "CFaceComm.h"
#include "sm_object.h"
#include "string_utils.h"
#include "urlcodec.h"
#include "std_base64.h"
#include "fit_ai_helper.h"
#include "CTools.h"
#include "http_helper.h"
#include <curl/curl.h>
#include <vector>
#include <ctime>
#include <sstream>


using std::string;
using std::vector;
using tenpay::credit::StringUtils;

const string CONF_FITAI_FACE_KEY = "fit_ai_face_check";                              // 人脸检测相关配置主键
const string FITAI_FACECHECK_URL = "/face_recognition_silent_gateway/face_comparing"; // 优图人脸比对接口地址

static int writer(char *data, size_t size, size_t nmemb, std::string *writerData)
{
     int len = size*nmemb;

     writerData->append(data, len);
     return len;
}

static std::map<std::string ,CURL *>g_addrCurlMap;
class CurlGlobalInit {
public:
    CurlGlobalInit() {
        curl_global_init(CURL_GLOBAL_ALL);
    }
	~CurlGlobalInit()
	{
		std::map<std::string,CURL* >::iterator iter = g_addrCurlMap.begin();
		for (; iter != g_addrCurlMap.end(); ++iter)
		{
			curl_easy_cleanup(iter->second);
			iter->second = NULL;
		}
	}
};
static CurlGlobalInit gCurlGlobalInit;


FaceRecognitionFitAI::FaceRecognitionFitAI(
            const std::string account,
            const int business_id,
            const long long int transaction_id,
            const std::string name,
            const std::string id,
            const std::string &image_data,
            const string &face_image_data
):str_facecheck_ip_(""), int_facecheck_port_(0),int_facecheck_modid_(0),
   int_facecheck_cmdid_(0), int_facecheck_timeout_(0), 
   str_idcard_num_(id), str_idcard_name_(name),  str_photo_b64_(""),
   str_account_(account), int_business_id_(business_id),
   int_seqno_(transaction_id),str_image_data_(image_data),
   str_face_image_data_(face_image_data), str_appid_(""), str_nonce_(""), 
   str_signature_(""), str_secret_key_("")
{ }

FaceRecognitionFitAI::~FaceRecognitionFitAI(){}

//sm_comm.h文件中错误码冲突，太过臃肿，将错误码转换在此完成
class ErrcodeTransition {
 public:
    ErrcodeTransition(int errcodeTmp, std::string strMsg)
    {
        errcode = errcodeTmp;
        strmsg = strMsg;
    }
    int errcode;
    string strmsg;
};

const std::map<int, ErrcodeTransition>::value_type map_errcode_transition[] =
{
std::map<int, ErrcodeTransition>::value_type(11001, ErrcodeTransition(ST_FACE_ERRCODE_IMAGE_FORMAT_INVALID, string("图片格式错误。"))),
std::map<int, ErrcodeTransition>::value_type(11002, ErrcodeTransition(ST_FACE_ERRCODE_IMAGE_FORMAT_INVALID, string("未检测到人脸。"))),
std::map<int, ErrcodeTransition>::value_type(10000, ErrcodeTransition(ST_FACE_ERRCODE_PARAM, string("身份证号码不合法。"))),//姓名、身份证或照片缺失,
std::map<int, ErrcodeTransition>::value_type(10001, ErrcodeTransition(ST_FACE_ERRCODE_AUTH, string("身份证号码和姓名不匹配。"))),
};

int map_length_fit = (sizeof(map_errcode_transition)/sizeof(std::map<int, ErrcodeTransition>::value_type));
const static std::map<int, ErrcodeTransition> m_ErrCodeMsgMap(map_errcode_transition, map_errcode_transition + map_length_fit);

int FaceRecognitionFitAI::GetErrMsgForErrCode(int errCode, int iDefErrCode,const std::string &strDefMsg, std::string &strErrMsg){
	DebugLog("FaceRecognitionFitAI strErrMsg:%s,retcode:%d",strDefMsg.c_str(),errCode);
	std::map<int, ErrcodeTransition>::const_iterator iter = m_ErrCodeMsgMap.find(errCode);
	if (iter != m_ErrCodeMsgMap.end())
	{
		strErrMsg = iter->second.strmsg;
		DebugLog("strErrMsg:%s,retcode:%d,%d",strErrMsg.c_str(),iter->second.errcode,errCode);
		return iter->second.errcode;
	}
	strErrMsg = strDefMsg;
	return iDefErrCode;
}


std::string FaceRecognitionFitAI::GenerateGignature(const std::string& time_stamp){
    std::string str_signature;
    str_signature = string("appid=") + str_appid_ + string("&nonce=") + str_nonce_ + \
    string("&idcard_name=") + str_idcard_name_ + string("&idcard_number=") + str_idcard_num_ + \
    string("&time_stamp=") + time_stamp;
    str_signature = Fit_AI_Tools::HmacSha256(str_secret_key_, str_signature);
    return str_signature;
}

/*
 * FITAI进行人脸比对,需要双照
 */
int FaceRecognitionFitAI::FaceCheck(
        int& ret_code,
        int& face_score,
        bool& status,
        string& ret_msg){
    status = false;
    ReadConf();

    str_nonce_ = Fit_AI_Tools::GenerateStr(16);
    str_appid_ = string("Lfp0iILmY0GG9aaMdM36NkWOGNmdyIDB");                // 后续将其写入配置文件
    str_secret_key_ = string("c2itnv7cYppwVVVlPKauZEuErFIa2Oe2");           //
    string nonce_hex = Fit_AI_Tools::StrToHex(str_nonce_);

    str_secret_key_ = Tools::MD5(str_secret_key_.c_str());
    string str_image_data_aes = Fit_AI_Tools::aes_128_gcm_encrypt(str_image_data_, str_secret_key_, str_nonce_);          //自拍照加密
    string str_face_image_data_aes = Fit_AI_Tools::aes_128_gcm_encrypt(str_face_image_data_, str_secret_key_, str_nonce_); //比对照加密

    std::time_t t = std::time(NULL);  // t is an integer type
    std::stringstream ss;
    ss << t;
    std::string str_time_stamp = ss.str();

    str_signature_ = GenerateGignature(str_time_stamp);

    struct curl_httppost *post = NULL;
    struct curl_httppost *last = 0;
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "nonce",
                 CURLFORM_COPYCONTENTS, nonce_hex.c_str(), CURLFORM_END);
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "time_stamp",
                 CURLFORM_COPYCONTENTS, str_time_stamp.c_str(), CURLFORM_END);
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "appid",
                 CURLFORM_COPYCONTENTS, str_appid_.c_str(), CURLFORM_END);
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "idcard_number",
                 CURLFORM_COPYCONTENTS, str_idcard_num_.c_str(), CURLFORM_END);
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "idcard_name",
                 CURLFORM_COPYCONTENTS, str_idcard_name_.c_str(), CURLFORM_END);
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "signature",
                 CURLFORM_COPYCONTENTS, str_signature_.c_str(), CURLFORM_END);
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "idcard_photo",
                 CURLFORM_BUFFER, "idcard_photo", CURLFORM_BUFFERPTR, str_image_data_aes.c_str(),
                 CURLFORM_BUFFERLENGTH, str_image_data_aes.length(), CURLFORM_END);
    curl_formadd(&post, &last, CURLFORM_COPYNAME, "user_photo",
                 CURLFORM_BUFFER, "user_photo", CURLFORM_BUFFERPTR, str_face_image_data_aes.c_str(),
                 CURLFORM_BUFFERLENGTH, str_face_image_data_aes.length(), CURLFORM_END);

    std::vector <std::string> header_vector;
    header_vector.push_back("Content-Type: multipart/form-data");
    header_vector.push_back("Expect: ");
    
    std::string rsp_str;
    std::stringstream ip_port_key;
    ip_port_key << str_facecheck_ip_ << ":" << int_facecheck_port_;
    // 获取 curl 操作描述符: 从缓存 map 读取或者重新生成
    std::map<std::string, CURL *>::iterator iter = g_addrCurlMap.find(ip_port_key.str());
    CURL *curl = NULL;
    if (iter != g_addrCurlMap.end()) {
        curl = iter->second;
    } else {
        curl = curl_easy_init();
    }

    std::string req_addr = std::string("http://") + ip_port_key.str() + FITAI_FACECHECK_URL;

    // 准备 post 请求的数据
    if (curl) {
        // 将新生成的 curl 文件操作符存入 cache
        g_addrCurlMap[ip_port_key.str()] = curl;

        curl_easy_setopt(curl, CURLOPT_URL, req_addr.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writer);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rsp_str);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, int_facecheck_timeout_);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
        curl_easy_setopt(curl, CURLOPT_PORT, int_facecheck_port_);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60);
        curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
        curl_easy_setopt(curl, CURLOPT_TCP_KEEPIDLE, 120L);
        curl_easy_setopt(curl, CURLOPT_TCP_KEEPINTVL, 60L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 0);
        curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);
    } else {
        ret_msg = "系统繁忙，请稍后再试。";
        return LOCAL_ERROR;
    }
    if (!header_vector.empty()) {
        struct curl_slist *headers = NULL; /* init to NULL is important */
        std::vector<std::string>::const_iterator iter = header_vector.begin();
        for (; iter != header_vector.end(); ++iter) {
            headers = curl_slist_append(headers, iter->c_str());
        }
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    CURLcode res_code;
    res_code = curl_easy_perform(curl);
    std::stringstream ss_msg;
    if (CURLE_OK != res_code) {
        ss_msg << req_addr << ";res_code:" << res_code;
        ret_msg = ss_msg.str();
        return SERVER_ERROR;
    }

    long http_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200) {
        ss_msg << req_addr << ";http_code is " << http_code;
        ret_msg = ss_msg.str();
        return RESPONSE_ERROR;
    }

    DebugLog("FitAI response:%s", rsp_str.c_str());
    
    // 返回json格式数据包进行解析
    Json::Reader json_reader;
    Json::Value json_content;            

    if (!json_reader.parse(rsp_str.c_str(), json_content, false)) {
        ErrorLog("FitAI face check, json from fitai's rsp parse failed.");
        return -1;
    }
    
    if (json_content["code"].isInt()) {
		ret_code = json_content["code"].asInt();
		if (0 != ret_code) {
			DebugLog("FitAI'rsp retcode:%d.",ret_code);
			ret_code = GetErrMsgForErrCode(ret_code, ST_FACE_ERRCODE_RECOGNITION, "核身失败。", ret_msg);
			return ret_code;
		}
		if (json_content["score"].isInt()) {
        	face_score = json_content["score"].asInt();	
		}
		if (json_content["message"].isString()) {
			DebugLog("FitAI'rsp message:%s", json_content["message"].asString().c_str());
		}
		if (json_content["status"].isInt()) {
			int res_status = json_content["status"].asInt();
			if (res_status == 1 || face_score >= 72) {
				status = true;
			} 
		}
        DebugLog("FITAI rsp's score:%d", face_score);
    } else {
		ErrorLog("FitAI's interface exception, no code.");
		return SERVER_ERROR;
    }

    return 0;
}



// 读取FITAI服务相关连接配置
void FaceRecognitionFitAI::ReadConf(){
    SM_COMM::GetFaceItemArguments(CONF_FITAI_FACE_KEY, int_facecheck_timeout_, str_facecheck_ip_, int_facecheck_port_, int_facecheck_modid_, int_facecheck_cmdid_);
}

// 保存人脸比对结果到 Log 表
void FaceRecognitionFitAI::AddRecognitionInfoToLog(
        const int retcode,
        const string &ret_msg,
        const int& face_score,
        const string &image_name,
        const int channel,
        const Json::Value channel_msg_json) {
    KVMap contentMap;
    CSmLogData logData;
    logData.Init();
    logData.pkey(int_seqno_);
    logData.data_time(SM_COMM::GetAuthTime(int_seqno_) * 1000);
    logData.channel(channel);
    logData.auth_type(SM_AUTH_TYPE_REG);
    logData.ent_no(int_business_id_);
    logData.account(str_account_);
    logData.content("");
    if (retcode == 1) {
       logData.result(SM_AUTH_RESULT_SUCCESS);
    } else {
        logData.result(RetCodeTransition(retcode));
    }
    contentMap.SetValue("name", str_idcard_name_);
    contentMap.SetValue("id", str_idcard_num_);
    contentMap.SetValue(SM_SCORE, face_score);
    contentMap.SetValue("image_name", image_name);


    Json::Value result_msg_json = SM_COMM::KVMapToJsonValue(contentMap);
    if(!channel_msg_json.isNull()){
        result_msg_json["channel_info"] = channel_msg_json;
    }
    Json::FastWriter fast_writer;
    string result_msg = StringUtils::trim(fast_writer.write(result_msg_json));
    InfoLog("AddRecognitionInfoToLog. Recognition Msg:%s", result_msg.c_str());
    logData.result_msg(regUrlEncode(result_msg));
    int iRet = logData.Add();
    if (iRet != 0) {
        ErrorLog("AddRecognitionInfoToLog. Add log failed. Ret:%d, Msg:%s, Data:%s",
                 iRet, logData.ErrMsg().c_str(), logData.ToString().c_str());
    }
    return;
}
