#include "face_recognition_huafu.h"
#include "sm_comm.h"
#include "CFaceComm.h"
#include "sm_object.h"
#include "string_utils.h"
#include "urlcodec.h"
#include "std_base64.h"
#include <vector>

using std::string;
using std::vector;
using tenpay::credit::StringUtils;

const string CONF_HUAFU_FACE_KEY = "huafu_face_check";       // 人脸检测相关配置主键
const string HUAFU_FACECHECK_URL = "/hfepay/face_image/check";// HuaFu人脸比对接口地址

FaceRecognitionHuaFu::FaceRecognitionHuaFu(
            const std::string account,
            const int business_id,
            const long long int transaction_id,
            const std::string name,
            const std::string id,
            const std::string &image_data
):str_facecheck_ip_(""), int_facecheck_port_(0),int_facecheck_modid_(0),
   int_facecheck_cmdid_(0), int_facecheck_timeout_(0), 
   str_idcard_num_(id), str_idcard_name_(name),  str_photo_b64_(""),
   str_account_(account), int_business_id_(business_id),
   int_seqno_(transaction_id),str_image_data_(image_data)
{ }

FaceRecognitionHuaFu::~FaceRecognitionHuaFu(){}

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
std::map<int, ErrcodeTransition>::value_type(-9, ErrcodeTransition(ST_FACE_ERRCODE_TIMEOUT, string("很抱歉，系统繁忙。"))),
std::map<int, ErrcodeTransition>::value_type(-8, ErrcodeTransition(ST_FACE_ERRCODE_TIMEOUT, string("很抱歉，系统繁忙。"))),
std::map<int, ErrcodeTransition>::value_type(-4, ErrcodeTransition(ST_FACE_ERRCODE_PARAM, string("很抱歉，参数信息不完整。"))),//姓名、身份证或照片缺失,
std::map<int, ErrcodeTransition>::value_type(-3, ErrcodeTransition(ST_FACE_ERRCODE_SYSTEM, string("很抱歉，系统错误。"))),
std::map<int, ErrcodeTransition>::value_type(-2, ErrcodeTransition(ST_FACE_ERRCODE_SYSTEM, string("很抱歉，系统错误。"))),
std::map<int, ErrcodeTransition>::value_type(2, ErrcodeTransition(ST_FACE_ERRCODE_TIMEOUT, string("很抱歉，系统繁忙。"))),
std::map<int, ErrcodeTransition>::value_type(3, ErrcodeTransition(ST_FACE_ERRCODE_AUTH,string("用户信息不存在。"))),
std::map<int, ErrcodeTransition>::value_type(5, ErrcodeTransition(ST_FACE_ERRCODE_AUTH, string("用户上传信息格式有误。"))),//用户身份信息有错
std::map<int, ErrcodeTransition>::value_type(6, ErrcodeTransition(ST_FACE_ERRCODE_AUTH, string("验证失败。"))),
std::map<int, ErrcodeTransition>::value_type(7, ErrcodeTransition(ST_FACE_ERRCODE_TIMEOUT, string("很抱歉，网络连接出错。"))),
};

int map_length = (sizeof(map_errcode_transition)/sizeof(std::map<int, ErrcodeTransition>::value_type));
const static std::map<int, ErrcodeTransition> m_ErrCodeMsgMap(map_errcode_transition, map_errcode_transition + map_length);

int FaceRecognitionHuaFu::GetErrMsgForErrCode(int errCode, int iDefErrCode,const std::string &strDefMsg, std::string &strErrMsg){
	DebugLog("FaceRecognitionHuaFu strErrMsg:%s,retcode:%d",strDefMsg.c_str(),errCode);
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

/*
 * HuaFu进行人脸比对,只用人脸照片即可
 */
int FaceRecognitionHuaFu::FaceCheck(
        int& ret_code,
        int& face_score,
        bool& status,
        string& ret_msg){
    status = false;
    ReadConf();

    //将图片进行base64编码
    int int_input_len = str_image_data_.size();
    vector<char>  vec_res;
    int int_buff_len = (int_input_len + 2)/3 * 4 + 4;
    vec_res.resize(int_buff_len, '\0');
    int int_result_len = 0;
    int ret = Stand_Base64::Encode((const unsigned char*)str_image_data_.c_str(), int_input_len, &vec_res[0], int_buff_len, &int_result_len);
    if (0 != ret) {
        ErrorLog("HuaFu Execute Encode image failed. Image size: %d",
         str_image_data_.size());
    } else {
        str_photo_b64_ = std::string(vec_res.begin(), vec_res.begin() + int_result_len);
    }

    // 构造请求 url
    stringstream ossUrl;
    ossUrl << "http://" << str_facecheck_ip_ << ":" << int_facecheck_port_ << HUAFU_FACECHECK_URL;
    string str_url = ossUrl.str();
    InfoLog("HuaFu FaceCheck, url:%s", str_url.c_str());
    
    // 构造请求 body
    stringstream oss_body;
    oss_body << "id=" << str_idcard_num_ << "&name=" << str_idcard_name_ << "&faceImageBase64=" <<str_photo_b64_;
    
    string str_body = oss_body.str();

    // 构造请求头
    vector <string> req_header;
    req_header.push_back("Expect:");
    req_header.push_back("POST " + HUAFU_FACECHECK_URL + " HTTP/1.1");
    req_header.push_back("application/x-www-form-urlencoded");


    string str_response;                            // 保存请求响应内容
    ret = SM_COMM::CurlPerform(str_url, int_facecheck_modid_, int_facecheck_cmdid_, str_facecheck_ip_, int_facecheck_port_,
                               int_facecheck_timeout_, &str_body[0], str_body.size(), req_header, str_response);

    InfoLog("FaceCheck, CurlPerform. Ret:%d, name: %s",
            ret, str_idcard_name_.c_str());
    if (ret != 0) {
        ErrorLog("HuaFu FaceCheck, CurlPerform failed. Ret:%d, name: %s",
                 ret, str_idcard_name_.c_str());
        ret_code = SM_COMM::GetErrMsgForErrCode(ret, ST_FACE_ERRCODE_TIMEOUT,
                                                 "系统繁忙, 请稍后再试。", ret_msg);
        return ret_code;
    }

    DebugLog("HuaFu response:%s", str_response.c_str());
    
    // 返回json格式数据包进行解析
    Json::Reader json_reader;
    Json::Value json_content;            

    if (!json_reader.parse(str_response.c_str(), json_content, false)) {
        ErrorLog("HuaFu face check, json from huafu's rsp parse failed.");
        return -1;
    }

    if (json_content["score"].isDouble()) {
        face_score = json_content["score"].asDouble();
        DebugLog("score:%d", face_score);
    }
    ret = json_content["retcode"].asInt();
    if ( 1 == ret) {
        status = true;
    } else if (0 != ret) {
            ret_code = GetErrMsgForErrCode(ret, ST_FACE_ERRCODE_RECOGNITION, "核身失败。", ret_msg);
            DebugLog("HuaFu FaceCheck. Check Face failed. ret_code:%d,ret_msg:%s", ret_code, ret_msg.c_str());
            return ret_code;
    }

    return 0;
}



// 读取HuaFu服务相关连接配置
void FaceRecognitionHuaFu::ReadConf(){
    SM_COMM::GetFaceItemArguments(CONF_HUAFU_FACE_KEY, int_facecheck_timeout_, str_facecheck_ip_, int_facecheck_port_, int_facecheck_modid_, int_facecheck_cmdid_);
}

// 保存人脸比对结果到 Log 表
void FaceRecognitionHuaFu::AddRecognitionInfoToLog(
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
