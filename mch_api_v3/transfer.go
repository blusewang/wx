package mch_api_v3

type TransferBatchesDetailItem struct {
	OutDetailNo    string `json:"out_detail_no"`
	TransferAmount int    `json:"transfer_amount"`
	TransferRemark string `json:"transfer_remark"`
	OpenId         string `json:"openid"`
	UserName       string `json:"user_name,omitempty"`
}
type TransferBatchesReq struct {
	AppId              string                      `json:"appid"`
	OutBatchNo         string                      `json:"out_batch_no"`
	BatchName          string                      `json:"batch_name"`
	BatchRemark        string                      `json:"batch_remark"`
	TotalAmount        int                         `json:"total_amount"`
	TotalNum           int                         `json:"total_num"`
	TransferDetailList []TransferBatchesDetailItem `json:"transfer_detail_list"`
	TransferSceneId    string                      `json:"transfer_scene_id,omitempty"`
	NotifyUrl          string                      `json:"notify_url,omitempty"`
}

type TransferBatchesResp struct {
	OutBatchNo  string `json:"out_batch_no"`
	BatchId     string `json:"batch_id"`
	CreateTime  string `json:"create_time"`
	BatchStatus string `json:"batch_status,omitempty"`
}
