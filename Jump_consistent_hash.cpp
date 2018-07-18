/* Jump consistent hash 函数的实现
 * Google的零内存消耗、均匀、快速、简洁的一致性哈希算法;
 * 根据配置权重来选择 OCR 识别引擎时，调用该函数
 * 根据流水号和桶的总数返回一个桶id，由该桶对应的数据引擎处理该请求.
 */
int32_t SM_COMM::JumpConsistentHash(uint64_t key, int32_t num_buckets) {
	// TODO 对流水号计算 CRC32后再计算 hash
	int64_t b = -1, j = 0;
	while (j < num_buckets) {
		b = j;
		key = key * 2862933555777941757ULL + 1;
		j = (b + 1) * (double(1LL << 31) / double((key >> 33) + 1));
	}
	return b;
}


// 做人脸比对时选择引擎（0:youtu,1:huafu,2:fit ai）
int CFaceUniform::FaceRecognitionChooseEngine() {
	// 如果通过配置文件判定走公安部，则必须选择youtu，直接返回
	if (m_bNc) {
		m_iFaceRecogEngine_ = FACE_RECOGNITION_YT_OPEN;
		DebugLog("FaceRecognitionChooseEngine, image_channel use NC");
		return 0;
	}

	int yt_open_weight = static_cast<int>(strtol(g_allVar.GetValue(
    RECOGNITION_ENGINE_WEIGHT_ITEM_NAME, ENGINE_YT_OPEN).c_str(), NULL, 10));
    int huafu_weight = static_cast<int>(strtol(g_allVar.GetValue(
            RECOGNITION_ENGINE_WEIGHT_ITEM_NAME, ENGINE_HUAFU).c_str(), NULL, 10));
    int fit_ai_weight = static_cast<int>(strtol(g_allVar.GetValue(
            RECOGNITION_ENGINE_WEIGHT_ITEM_NAME, ENGINE_FIT_AI).c_str(), NULL, 10));
    DebugLog("FaceRecognitionChooseEngine, yt_open:%d, huafu:%d, fit_ai:%d ", yt_open_weight, huafu_weight, fit_ai_weight);
    int total_weight = yt_open_weight + huafu_weight + fit_ai_weight;
    int hash_value = SM_COMM::JumpConsistentHash(m_ddwSeqNo, total_weight);
    if (hash_value < yt_open_weight) {
        DebugLog("FaceRecognitionChooseEngine. Hash value is %d, chose engine %s", hash_value, ENGINE_YT_OPEN.c_str());
		m_iFaceRecogEngine_ = FACE_RECOGNITION_YT_OPEN;
    } else if (hash_value < yt_open_weight + huafu_weight) {
        DebugLog("FaceRecognitionChooseEngine. Hash value is %d, chose engine %s", hash_value, ENGINE_HUAFU.c_str());
        m_iFaceRecogEngine_ = FACE_RECOGNITION_HUAFU;
    } else {
        DebugLog("FaceRecognitionChooseEngine. Hash value is %d, chose engine %s", hash_value, ENGINE_FIT_AI.c_str());
		m_iFaceRecogEngine_ = FACE_RECOGNITION_FIT_AI;
    }
	return 0;
}
