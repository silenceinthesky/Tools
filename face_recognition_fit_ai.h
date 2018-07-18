#ifndef FACE_RECOGNITION_FIT_AI_H_
#define FACE_RECOGNITION_FIT_AI_H_


#include <string>
#include "json/json.h"


/*
 * 封装FIT AI组的人脸比对服务（比对照支持网纹照和非网纹照）对 FCGI 提供统一的操作接口
 *
 * 使用方法: FCGI 传入必要的参数构造对象, 然后调用 FaceCheck 方法即可.
 *         本接口会调用FIT AI人脸比对服务进行人脸比对
 *         同时提供接口将结果保存到Log表.
 */
class FaceRecognitionFitAI {
public:
    FaceRecognitionFitAI(
            const std::string account,
            const int business_id,
            const long long int transaction_id,
            const std::string name,
            const std::string id,
            const std::string &image_data,
            const std::string &face_image_data);

    virtual ~FaceRecognitionFitAI();

    // 供fcgi调用接口，不返网纹照
    int FaceCheck(
            int &int_reuslt,
            int &int_face_score,
            bool &b_status,
            std::string &str_err_msg);

    // 保存日志信息到log表-华付
    void AddRecognitionInfoToLog(
            const int retcode,
            const std::string &ret_msg,
            const int &face_score,
            const std::string &image_name,      // 用户上传自拍照文件名
            const int channel,
            const Json::Value channel_msg_json = Json::nullValue);

private:
    // 读取配置文件
    void ReadConf();
    std::string GenerateGignature(const std::string& time_stamp);
    //错误码转换表，返回给用户的错误码仍旧是sm_comm.h中的错误码定义，但映射关系在本文件中定义
    int GetErrMsgForErrCode(int errCode, int iDefErrCode, const std::string &strDefMsg, std::string &strErrMsg);

    // 配置文件获取huafu所使用的Modid、Cmdid、ip、port
    std::string str_facecheck_ip_;
    int int_facecheck_port_;
    int int_facecheck_modid_;
    int int_facecheck_cmdid_;
    int int_facecheck_timeout_;
    
    // 华付接口所需信息,姓名、身份证、照片base编码
    std::string str_idcard_num_;
    std::string str_idcard_name_;
    std::string str_photo_b64_;

    // 用户的其他信息，用于写入log表，方便tdw统计区分
    const std::string str_account_;             // 用户账户
    const int int_business_id_;                 // 商户号
    const long long int int_seqno_;             // 流水号
    const std::string &str_image_data_;         // 需要检测的照片文件
    const std::string &str_face_image_data_;    // 比对照片数据

    // 接口所需信息
    std::string str_appid_;
    std::string str_nonce_;
    std::string str_signature_;
    std::string str_secret_key_;
    
};

#endif