// Copyright 2022 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package mch_api_v3

type ProfitSharingOrdersReqReceiver struct {
	Type        string `json:"type"`
	Account     string `json:"account"`
	Name        string `json:"name,omitempty"`
	Amount      int64  `json:"amount"`
	Description string `json:"description"`
}
type ProfitSharingOrdersReq struct {
	SubMchid        string                           `json:"sub_mchid,omitempty"`
	AppId           string                           `json:"appid"`
	SubAppid        string                           `json:"sub_appid,omitempty"`
	TransactionId   string                           `json:"transaction_id"`
	OutOrderNo      string                           `json:"out_order_no"`
	UnfreezeUnsplit bool                             `json:"unfreeze_unsplit"`
	Receivers       []ProfitSharingOrdersReqReceiver `json:"receivers"`
}

type ProfitSharingOrdersRespReceiver struct {
	ProfitSharingOrdersReqReceiver
	Result     string `json:"result"`
	FailReason string `json:"fail_reason"`
	DetailId   string `json:"detail_id"`
	CreateTime string `json:"create_time"`
	FinishTime string `json:"finish_time"`
}

type ProfitSharingOrdersResp struct {
	TransactionId string                             `json:"transaction_id"`
	OutOrderNo    string                             `json:"out_order_no"`
	OrderId       string                             `json:"order_id"`
	State         string                             `json:"state"`
	Receivers     *[]ProfitSharingOrdersRespReceiver `json:"receivers,omitempty"`
}

type ProfitSharingOrdersQueryResp struct {
	TransactionId string                             `json:"transaction_id"`
	OutOrderNo    string                             `json:"out_order_no"`
	OrderId       string                             `json:"order_id"`
	State         string                             `json:"state"`
	Receivers     *[]ProfitSharingOrdersRespReceiver `json:"receivers,omitempty"`
}

type ProfitSharingOrdersUnfreezeReq struct {
	SubMchid      string `json:"sub_mchid,omitempty"`
	TransactionId string `json:"transaction_id"`
	OutOrderNo    string `json:"out_order_no"`
	Description   string `json:"description"`
}

type ProfitSharingOrdersUnfreezeResp ProfitSharingOrdersQueryResp

type ProfitSharingOrdersAddReq struct {
	SubMchid       string `json:"sub_mchid,omitempty"`
	AppId          string `json:"appid"`
	SubAppid       string `json:"sub_appid,omitempty"`
	Type           string `json:"type"`
	Account        string `json:"account"`
	Name           string `json:"name,omitempty"`
	RelationType   string `json:"relation_type"`
	CustomRelation string `json:"custom_relation,omitempty"`
}

type ProfitSharingOrdersDeleteReq struct {
	SubMchid string `json:"sub_mchid,omitempty"`
	AppId    string `json:"appid"`
	SubAppid string `json:"sub_appid,omitempty"`
	Type     string `json:"type"`
	Account  string `json:"account"`
}

type ProfitSharingMerchantConfigsResp struct {
	SubMchid string `json:"sub_mchid"`
	MaxRatio int64  `json:"max_ratio"`
}
