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
	AppId           string                           `json:"appid"`
	TransactionId   string                           `json:"transaction_id"`
	OutOrderNo      string                           `json:"out_order_no"`
	UnfreezeUnsplit bool                             `json:"unfreeze_unsplit"`
	Receivers       []ProfitSharingOrdersReqReceiver `json:"receivers"`
}

type ProfitSharingOrdersResp struct {
	TransactionId string `json:"transaction_id"`
	OutOrderNo    string `json:"out_order_no"`
	OrderId       string `json:"order_id"`
	State         string `json:"state"`
	Receivers     *[]struct {
		Type        string `json:"type"`
		Account     string `json:"account"`
		Amount      int64  `json:"amount"`
		Description string `json:"description"`
		Result      string `json:"result,omitempty"`
		FailReason  string `json:"fail_reason"`
		CreateTime  string `json:"create_time"`
		FinishTime  string `json:"finish_time"`
		DetailId    string `json:"detail_id"`
	} `json:"receivers,omitempty"`
}

type ProfitSharingOrdersQueryResp struct {
	TransactionId string `json:"transaction_id"`
	OutOrderNo    string `json:"out_order_no"`
	OrderId       string `json:"order_id"`
	State         string `json:"state"`
	Receivers     *[]struct {
		Type        string `json:"type"`
		Account     string `json:"account"`
		Amount      int64  `json:"amount"`
		Description string `json:"description"`
		Result      string `json:"result,omitempty"`
		FailReason  string `json:"fail_reason"`
		CreateTime  string `json:"create_time"`
		FinishTime  string `json:"finish_time"`
		DetailId    string `json:"detail_id"`
	} `json:"receivers,omitempty"`
}

type ProfitSharingOrdersUnfreezeReq struct {
	TransactionId string `json:"transaction_id"`
	OutOrderNo    string `json:"out_order_no"`
	Description   string `json:"description"`
}

type ProfitSharingOrdersUnfreezeResp ProfitSharingOrdersQueryResp

type ProfitSharingOrdersAddReq struct {
	AppId          string `json:"appid"`
	Type           string `json:"type"`
	Account        string `json:"account"`
	Name           string `json:"name,omitempty"`
	RelationType   string `json:"relation_type"`
	CustomRelation string `json:"custom_relation,omitempty"`
}
