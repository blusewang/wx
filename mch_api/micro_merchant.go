// Copyright 2022 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package mch_api

// MicroMerchantApplymentData 小微商户入驻申请表
type MicroMerchantApplymentData struct {
	MchBase
	Version              string `xml:"version"`
	CertSn               string `xml:"cert_sn"`
	BusinessCode         string `xml:"business_code"`
	IdCardCopy           string `xml:"id_card_copy"`
	IdCardNational       string `xml:"id_card_national"`
	IdCardName           string `xml:"id_card_name"`
	IdCardNumber         string `xml:"id_card_number"`
	IdCardValidTime      string `xml:"id_card_valid_time"`
	AccountName          string `xml:"account_name"`
	AccountBank          string `xml:"account_bank"`
	BankAddressCode      string `xml:"bank_address_code"`
	BankName             string `xml:"bank_name,omitempty"`
	AccountNumber        string `xml:"account_number"`
	StoreName            string `xml:"store_name"`
	StoreAddressCode     string `xml:"store_address_code"`
	StoreStreet          string `xml:"store_street"`
	StoreLongitude       string `xml:"store_longitude,omitempty"`
	StoreLatitude        string `xml:"store_latitude,omitempty"`
	StoreEntrancePic     string `xml:"store_entrance_pic"`
	IndoorPic            string `xml:"indoor_pic"`
	AddressCertification string `xml:"address_certification,omitempty"`
	MerchantShortName    string `xml:"merchant_short_name"`
	ServicePhone         string `xml:"service_phone"`
	ProductDesc          string `xml:"product_desc"`
	Rate                 string `xml:"rate"`
	BusinessAdditionDesc string `xml:"business_addition_desc,omitempty"`
	BusinessAdditionPics string `xml:"business_addition_pics,omitempty"`
	Contact              string `xml:"contact"`
	ContactPhone         string `xml:"contact_phone"`
	ContactEmail         string `xml:"contact_email,omitempty"`
}

// MicroMerchantApplymentResp 小微商户入驻申请提交结果
type MicroMerchantApplymentResp struct {
	MchBaseResponse
	MchBase
	ErrParam    string `xml:"err_param,omitempty"`
	ApplymentId string `xml:"applyment_id"`
}

// MicroMerchantApplymentGetStateData 小微商户入驻查询
type MicroMerchantApplymentGetStateData struct {
	MchBase
	ApplymentId  string `xml:"applyment_id,omitempty"`
	BusinessCode string `xml:"business_code,omitempty"`
}

// MicroMerchantApplymentGetStateResp 小微商户入驻查询结果
type MicroMerchantApplymentGetStateResp struct {
	MchBaseResponse
	MchBase
	ApplymentId        string `xml:"applyment_id"`
	ApplymentState     string `xml:"applyment_state"`
	ApplymentStateDesc string `xml:"applyment_state_desc"`
	SubMchId           string `xml:"sub_mch_id,omitempty"`
	SignUrl            string `xml:"sign_url,omitempty"`
	AuditDetail        string `xml:"audit_detail,omitempty"`
}
