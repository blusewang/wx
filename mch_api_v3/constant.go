// Copyright 2022 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package mch_api_v3

type MchApiV3 string

const (
	// OtherCertificates 获取平台证书列表
	OtherCertificates = "certificates"
	OtherUploadImage  = "merchant/media/upload"
	OtherUploadVideo  = "merchant/media/video_upload"

	// PartnerApplyment4Sub 特约商户进件申请单
	PartnerApplyment4Sub = "applyment4sub/applyment/"

	// PartnerApplymentQuery 特约商户进件申请状态查询
	PartnerApplymentQuery = "applyment4sub/applyment/business_code/"

	// PartnerJsApiTransaction 服务商JSAPI下单
	PartnerJsApiTransaction = "pay/partner/transactions/jsapi"

	// PartnerAppTransaction 服务商App下单
	PartnerAppTransaction = "pay/partner/transactions/app"

	// JsApiTransaction JSAPI下单
	JsApiTransaction = "pay/transactions/jsapi"

	// AppTransaction App下单
	AppTransaction = "pay/transactions/app"

	// ProfitSharingOrders 请求分账
	ProfitSharingOrders = "profitsharing/orders"

	// ProfitSharingOrdersUnfreeze 解冻剩余资金
	ProfitSharingOrdersUnfreeze = "profitsharing/orders/unfreeze"

	// ProfitSharingOrdersAdd 添加分账接收方
	ProfitSharingOrdersAdd = "profitsharing/receivers/add"

	// ProfitSharingOrdersDelete 删除分账接收方
	ProfitSharingOrdersDelete = "profitsharing/receivers/delete"
)

type ErrorResp struct {
	Code   string `json:"code"`
	Detail struct {
		Location string `json:"location"`
		Value    string `json:"value"`
	} `json:"detail"`
	Message string `json:"message"`
}
