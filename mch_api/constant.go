// Copyright 2020 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package mch_api

type MchApi string

const (
	// PayUnifiedOrder 微信下单
	PayUnifiedOrder = "pay/unifiedorder"
	// PayOrderQuery 支付结果查询
	PayOrderQuery = "pay/orderquery"
	// PayRefund 退款
	PayRefund = "secapi/pay/refund"
	// PayProfitSharing 请求单次分账
	PayProfitSharing = "secapi/pay/profitsharing"
	// PayProfitSharingFinish 结束分账请求
	PayProfitSharingFinish = "secapi/pay/profitsharingfinish"
	// BankPay 企业付款到银行卡
	BankPay = "mmpaysptrans/pay_bank"
	// BankQuery 付款到银行卡结果查询
	BankQuery = "mmpaysptrans/query_bank"
	// RedPackSend 发红包
	RedPackSend = "mmpaymkttransfers/sendredpack"
	// RedPackInfo 红包状态查询
	RedPackInfo = "mmpaymkttransfers/gethbinfo"
	// Transfer 企业付款至零钱
	Transfer = "mmpaymkttransfers/promotion/transfers"
	// PublicKey 获取RSA公钥API获取RSA公钥
	PublicKey = "https://fraud.mch.weixin.qq.com/risk/getpublickey"
)

type MchSignType string

const (
	MchSignTypeMD5        = "MD5"
	MchSignTypeHMACSHA256 = "HMAC-SHA256"
)
