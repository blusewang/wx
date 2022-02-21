// Copyright 2022 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package mch_api_v3

import "time"

type Amount struct {
	Total    int64  `json:"total"`
	Currency string `json:"currency,omitempty"`
}
type Payer struct {
	OpenId string `json:"openid"`
}

type JsApiTransactionReq struct {
	AppId       string `json:"appid"`
	MchId       string `json:"mchid"`
	Description string `json:"description"`
	OutTradeNo  string `json:"out_trade_no"`
	TimeExpire  string `json:"time_expire,omitempty"`
	Attach      string `json:"attach,omitempty"`
	NotifyUrl   string `json:"notify_url"`
	GoodsTag    string `json:"goods_tag,omitempty"`
	Amount      Amount `json:"amount"`
	Payer       Payer  `json:"payer"`
}

type JsApiTransactionResp struct {
	PrepayId string `json:"prepay_id"`
}

type AppTransactionReq JsApiTransactionReq

type AppTransactionResp JsApiTransactionResp

type NotifyPayResult struct {
	Id           string `json:"id"`
	CreateTime   string `json:"create_time"`
	EventType    string `json:"event_type"`
	ResourceType string `json:"resource_type"`
	Summary      string `json:"summary"`
	Resource     struct {
		Algorithm      string `json:"algorithm"`
		Ciphertext     string `json:"ciphertext"`
		AssociatedData string `json:"associated_data,omitempty"`
		OriginalType   string `json:"original_type"`
		Nonce          string `json:"nonce"`
	} `json:"resource"`
}

type NotifyResource struct {
	Appid         string    `json:"appid,omitempty"`
	Mchid         string    `json:"mchid,omitempty"`
	SpAppid       string    `json:"sp_appid,omitempty"`
	SpMchid       string    `json:"sp_mchid,omitempty"`
	SubAppid      string    `json:"sub_appid,omitempty"`
	OutTradeNo    string    `json:"out_trade_no"`
	TransactionId string    `json:"transaction_id"`
	TradeType     string    `json:"trade_type"`
	TradeState    string    `json:"trade_state"`
	TradeStatDesc string    `json:"trade_stat_desc"`
	BankType      string    `json:"bank_type"`
	Attach        string    `json:"attach,omitempty"`
	SuccessTime   time.Time `json:"success_time"`
	Amount        struct {
		Total         int64  `json:"total"`
		PayerTotal    int64  `json:"payer_total"`
		Currency      string `json:"currency"`
		PayerCurrency string `json:"payer_currency"`
	} `json:"amount"`
	Payer struct {
		Openid    string `json:"openid,omitempty"`
		SpOpenid  string `json:"sp_openid,omitempty"`
		SubOpenid string `json:"sub_openid,omitempty"`
	} `json:"payer"`
	SceneInfo struct {
		DeviceId string `json:"device_id,omitempty"`
	} `json:"scene_info,omitempty"`
}
