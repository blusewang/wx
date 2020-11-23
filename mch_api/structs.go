// Copyright 2020 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package mch_api

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
)

type MchBase struct {
	XMLName  xml.Name `xml:"xml"`
	MchId    string   `xml:"mch_id,omitempty"`
	AppId    string   `xml:"appid,omitempty"`
	NonceStr string   `xml:"nonce_str"`
	Sign     string   `xml:"sign"`
	SignType string   `xml:"sign_type,omitempty"`
}

type MchBaseResponse struct {
	XMLName    xml.Name `xml:"xml"`
	ReturnCode string   `xml:"return_code"`
	ReturnMsg  string   `xml:"return_msg"`
	ResultCode string   `xml:"result_code,omitempty"`
	ErrCode    string   `xml:"err_code,omitempty"`
	ErrCodeDes string   `xml:"err_code_des,omitempty"`
}

// 是否成功处理
func (m MchBaseResponse) IsSuccess() bool {
	return m.ReturnCode == "SUCCESS" && m.ResultCode == "SUCCESS" && (m.ErrCode == "SUCCESS" || m.ErrCode == "")
}

// 如果出错，是否是微信程序错误
func (m MchBaseResponse) IsUnCertain() bool {
	return m.ErrCode == "SYSTEMERROR"
}

// 转为Golang错误
func (m MchBaseResponse) ToError() error {
	if m.ErrCodeDes != "" {
		return errors.New(fmt.Sprintf("%v %v", m.ErrCode, m.ErrCodeDes))
	} else if m.ReturnMsg != "" {
		return errors.New(fmt.Sprintf("%v %v", m.ReturnCode, m.ReturnMsg))
	} else {
		return nil
	}
}

// `ProfitSharing`设置为"Y"为分账定单标记。
// 不设置，或设置为"N"，为普通定单
type PayUnifiedOrderData struct {
	MchBase
	DeviceInfo     string `xml:"device_info"`
	Body           string `xml:"body"`
	OutTradeNo     string `xml:"out_trade_no"`
	TotalFee       int64  `xml:"total_fee"`
	SpBillCreateIp string `xml:"spbill_create_ip"`
	NotifyUrl      string `xml:"notify_url"`
	TradeType      string `xml:"trade_type"`
	Attach         string `xml:"attach"`
	ProfitSharing  string `xml:"profit_sharing,omitempty"`
}

type PayUnifiedOrderRes struct {
	MchBaseResponse
	MchBase
	PrepayId string `xml:"prepay_id"`
}

// 支付成功通知
type PayNotify struct {
	MchBaseResponse
	MchBase
	DeviceInfo         string `xml:"device_info"`
	OpenId             string `xml:"openid"`
	IsSubscribe        string `xml:"is_subscribe"`
	TradeType          string `xml:"trade_type"`
	BankType           string `xml:"bank_type"`
	TotalFee           int64  `xml:"total_fee"`
	SettlementTotalFee int64  `xml:"settlement_total_fee"`
	FeeType            string `xml:"fee_type"`
	CashFee            int64  `xml:"cash_fee"`
	CashFeeType        string `xml:"cash_fee_type"`
	CouponFee          int64  `xml:"coupon_fee"`
	CouponCount        int64  `xml:"coupon_count"`
	CouponType0        string `xml:"coupon_type_0"`
	CouponId0          string `xml:"coupon_id_0"`
	CouponFee0         int64  `xml:"coupon_fee_0"`
	CouponType1        string `xml:"coupon_type_1"`
	CouponId1          string `xml:"coupon_id_1"`
	CouponFee1         int64  `xml:"coupon_fee_1"`
	CouponType2        string `xml:"coupon_type_2"`
	CouponId2          string `xml:"coupon_id_2"`
	CouponFee2         int64  `xml:"coupon_fee_2"`
	CouponType3        string `xml:"coupon_type_3"`
	CouponId3          string `xml:"coupon_id_3"`
	CouponFee3         int64  `xml:"coupon_fee_3"`
	TransactionId      string `xml:"transaction_id"`
	OutTradeNo         string `xml:"out_trade_no"`
	Attach             string `xml:"attach"`
	TimeEnd            string `xml:"time_end"`
}

// 回复支付成功通知
type PayNotifyRes MchBaseResponse

type PayOrderQueryData struct {
	MchBase
	OutTradeNo string `xml:"out_trade_no"`
}

type PayOrderQueryRes PayNotify

type PayRefundData struct {
	MchBase
	TransactionId string `xml:"transaction_id"`
	OutTradeNo    string `xml:"out_trade_no"`
	OutRefundNo   string `xml:"out_refund_no"`
	TotalFee      int64  `xml:"total_fee"`
	RefundFee     int64  `xml:"refund_fee"`
	RefundDesc    string `xml:"refund_desc"`
	NotifyUrl     string `xml:"notify_url"`
}

type PayRefundRes struct {
	MchBaseResponse
	MchBase
	TransactionId string `xml:"transaction_id"`
	OutTradeNo    string `xml:"out_trade_no"`
	OutRefundNo   string `xml:"out_refund_no"`
	RefundId      string `xml:"refund_id"`
	RefundFee     int64  `xml:"refund_fee"`
	TotalFee      int64  `xml:"total_fee"`
	CashFee       int64  `xml:"cash_fee"`
}

// 分账结果中的接收者
type PayProfitSharingReceiver struct {
	Type        string `json:"type"`
	Account     string `json:"account"`
	Amount      int64  `json:"amount"`
	Description string `json:"description"`
}

type PayProfitSharingData struct {
	MchBase
	TransactionId string `xml:"transaction_id"`
	OutOrderNo    string `xml:"out_order_no"`
	Receivers     string `xml:"receivers"`
}

func (ppsd *PayProfitSharingData) SerReceivers(list []PayProfitSharingReceiver) (err error) {
	raw, err := json.Marshal(list)
	if err != nil {
		return
	}
	ppsd.Receivers = string(raw)
	return
}

type PayProfitSharingRes struct {
	MchBaseResponse
	MchBase
	TransactionId string `xml:"transaction_id"`
	OutOrderNo    string `xml:"out_order_no"`
	OrderId       string `xml:"order_id"`
}

type PayProfitSharingFinishData struct {
	MchBase
	TransactionId string `xml:"transaction_id"`
	OutOrderNo    string `xml:"out_order_no"`
	Description   string `xml:"description"`
}

type PayProfitSharingFinishRes PayProfitSharingRes

type BankPayData struct {
	MchBase
	PartnerTradeNo string `xml:"partner_trade_no"`
	EncBankNo      string `xml:"enc_bank_no"`
	EncTrueName    string `xml:"enc_true_name"`
	BankCode       string `xml:"bank_code"`
	AmountFen      int64  `xml:"amount"`
	Desc           string `xml:"desc"`
}

type BankPayRes struct {
	MchBaseResponse
	PartnerTradeNo string `xml:"partner_trade_no"`
	AmountFen      int64  `xml:"amount"`
	PaymentNo      string `xml:"payment_no"`
	CMmsAmt        int64  `xml:"cmms_amt"`
}

type BankQueryData struct {
	MchBase
	PartnerTradeNo string `xml:"partner_trade_no"`
}

type BankQueryRes struct {
	MchBaseResponse
	PartnerTradeNo string `xml:"partner_trade_no"`
	PaymentNo      string `xml:"payment_no"`
	AmountFen      int64  `xml:"amount"`
	Status         string `xml:"status"`
	CMmsAmtFen     int64  `xml:"cmms_amt"`
	CreateTime     string `xml:"create_time"`
	PaySuccessTime string `xml:"pay_succ_time"`
	Reason         string `xml:"reason"`
}

type RedPackSendData struct {
	MchBase
	MchBillNo   string `xml:"mch_billno"`
	WxAppId     string `xml:"wxappid"`
	SendName    string `xml:"send_name"`
	ReOpenId    string `xml:"re_openid"`
	TotalAmount int    `xml:"total_amount"`
	TotalNum    int    `xml:"total_num"`
	Wishing     string `xml:"wishing"`
	ClientIp    string `xml:"client_ip"`
	ActName     string `xml:"act_name"`
	Remark      string `xml:"remark"`
}

type RedPackSendRes struct {
	MchBaseResponse
	MchBillNo   string `xml:"mch_billno"`
	MchId       string `xml:"mch_id"`
	WxAppId     string `xml:"wxappid"`
	ReOpenId    string `xml:"re_openid"`
	TotalAmount int    `xml:"total_amount"`
	SendListId  string `xml:"send_listid"`
}

type RedPackInfoData struct {
	MchBase
	MchBillNo string `xml:"mch_billno"`
	BillType  string `xml:"bill_type"`
}

type RedPackInfoRes struct {
	MchBaseResponse
	MchBillNo    string  `xml:"mch_billno"`
	MchId        string  `xml:"mch_id"`
	Status       string  `xml:"status"`
	SendType     string  `xml:"send_type"`
	HbType       string  `xml:"hb_type"`
	Reason       *string `xml:"reason"`
	SendTime     string  `xml:"send_time"`
	RefundTime   *string `xml:"refund_time"`
	RefundAmount *int    `xml:"refund_amount"`
	Wishing      *string `xml:"wishing"`
	Remark       *string `xml:"remark"`
	ActName      *string `xml:"act_name"`
	HbList       []struct {
		HbInfo []struct {
			OpenId  string `xml:"openid"`
			Amount  int    `xml:"amount"`
			RcvTime string `xml:"rcv_time"`
		} `xml:"hbinfo"`
	} `xml:"hblist"`
}

type TransferData struct {
	XMLName        xml.Name `xml:"xml"`
	NonceStr       string   `xml:"nonce_str"`
	Sign           string   `xml:"sign"`
	SignType       string   `xml:"sign_type,omitempty"`
	MchId          string   `xml:"mchid"`
	MchAppId       string   `xml:"mch_appid"`
	PartnerTradeNo string   `xml:"partner_trade_no"`
	OpenId         string   `xml:"openid"`
	CheckName      string   `xml:"check_name"`
	ReUserName     string   `xml:"re_user_name"`
	Amount         int      `xml:"amount"`
	Desc           string   `xml:"desc"`
	SpBillCreateIp string   `xml:"spbill_create_ip"`
}

type TransferRes struct {
	MchBaseResponse
	MchId          string `xml:"mchid"`
	MchAppId       string `xml:"mch_appid"`
	NonceStr       string `xml:"nonce_str"`
	PartnerTradeNo string `xml:"partner_trade_no"`
	PaymentNo      string `xml:"payment_no"`
	PaymentTime    string `xml:"payment_time"`
}

type PublicKeyData struct {
	MchBase
}

type PublicKeyRes struct {
	MchBaseResponse
	PubKey string `xml:"pub_key"`
}
