// Copyright 2022 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package mch_api_v3

type PartnerPayer struct {
	SpOpenid  string `json:"sp_openid,omitempty"`
	SubOpenid string `json:"sub_openid,omitempty"`
}
type PartnerJsApiTransactionReq struct {
	SpAppId     string       `json:"sp_appid"`
	SpMchId     string       `json:"sp_mchid"`
	SubAppid    string       `json:"sub_appid,omitempty"`
	SubMchId    string       `json:"sub_mchid"`
	Description string       `json:"description"`
	OutTradeNo  string       `json:"out_trade_no"`
	TimeExpire  string       `json:"time_expire,omitempty"`
	Attach      string       `json:"attach,omitempty"`
	NotifyUrl   string       `json:"notify_url"`
	GoodsTag    string       `json:"goods_tag,omitempty"`
	Amount      Amount       `json:"amount"`
	Payer       PartnerPayer `json:"payer"`
}

type PartnerJsApiTransactionResp JsApiTransactionResp
