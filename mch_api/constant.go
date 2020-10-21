// Copyright 2020 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package mch_api

type MchApi string

const (
	PayUnifiedOrder        = "pay/unifiedorder"                                  // 微信下单
	PayOrderQuery          = "pay/orderquery"                                    // 支付结果查询
	PayRefund              = "secapi/pay/refund"                                 // 退款
	PayProfitSharing       = "secapi/pay/profitsharing"                          // 请求单次分账
	PayProfitSharingFinish = "secapi/pay/profitsharingfinish"                    // 结束分账请求
	BankPay                = "mmpaysptrans/pay_bank"                             // 企业付款到银行卡
	BankQuery              = "mmpaysptrans/query_bank"                           // 付款到银行卡结果查询
	RedPackSend            = "mmpaymkttransfers/sendredpack"                     // 发红包
	RedPackInfo            = "mmpaymkttransfers/gethbinfo"                       // 红包状态查询
	Transfer               = "mmpaymkttransfers/promotion/transfers"             // 企业付款至零钱
	PublicKey              = "https://fraud.mch.weixin.qq.com/risk/getpublickey" // 获取RSA公钥API获取RSA公钥
)

type MchSignType string

const (
	MchSignTypeMD5        = "MD5"
	MchSignTypeHMACSHA256 = "HMAC-SHA256"
)
