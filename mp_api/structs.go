package mp_api

import (
	"errors"
	"fmt"
)

type MpBaseResp struct {
	ErrCode int64  `json:"errcode,omitempty"`
	ErrMsg  string `json:"errmsg,omitempty"`
}

func (mbr MpBaseResp) IsError() bool {
	return mbr.ErrCode != 0
}

func (mbr MpBaseResp) ToError() error {
	return errors.New(fmt.Sprintf("微信错误: %v", mbr.ErrMsg))
}
