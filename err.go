package wxApi

import (
	"encoding/json"
	"fmt"
)

type wxErr struct {
	ErrCode int64 `json:"errcode"`
	ErrMsg string `json:"errmsg"`
}

type mchErr struct {
	ReturnCode string `xml:"return_code"`
	ReturnMsg string `xml:"return_msg"`
	ResultCode string `xml:"result_code"`
	ErrCode string `xml:"err_code"`
	ErrCodeDes string `xml:"err_code_des"`
}
func (m mchErr) IsRequestSuccess() bool {
	return m.ReturnCode == "SUCCESS" && m.ResultCode == "SUCCESS" && m.ErrCode == "SUCCESS"
}

func (m mchErr) IsBankPayUnCertain() bool {
	return m.ErrCode == "SYSTEMERROR"
}

func parseJsonErr(raw []byte) (err error) {
	var e wxErr
	err = json.Unmarshal(raw,&e)
	if err != nil {return}
	if e.ErrCode > 0 {err = fmt.Errorf("微信提示: %v",e.ErrMsg)}
	return
}
