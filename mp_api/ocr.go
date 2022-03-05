// Copyright 2022 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package mp_api

type OcrBaseQuery struct {
	ImgUrl string `url:"img_url"`
}

type OcrBandCardResp struct {
	MpBaseResp
	Id string `json:"id"`
}

type OcrBusinessLicenseResp struct {
	MpBaseResp
	RegNum              string `json:"reg_num"`
	Serial              string `json:"serial"`
	LegalRepresentative string `json:"legal_representative"`
	EnterpriseName      string `json:"enterprise_name"`
	TypeOfOrganization  string `json:"type_of_organization"`
	Address             string `json:"address"`
	TypeOfEnterprise    string `json:"type_of_enterprise"`
	BusinessScope       string `json:"business_scope"`
	RegisteredCapital   string `json:"registered_capital"`
	PaidInCapital       string `json:"paid_in_capital"`
	ValidPeriod         string `json:"valid_period"`
	RegisteredDate      string `json:"registered_date"`
}

type OcrIdCardResp struct {
	MpBaseResp
	Type        string `json:"type"`
	Name        string `json:"name"`
	Id          string `json:"id"`
	Addr        string `json:"addr"`
	Gender      string `json:"gender"`
	Nationality string `json:"nationality"`
	ValidDate   string `json:"valid_date"`
}
