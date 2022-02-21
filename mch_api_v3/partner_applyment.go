// Copyright 2022 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package mch_api_v3

type PartnerApplymentSubjectType string

const (
	PartnerApplymentSubjectTypePerson     = "SUBJECT_TYPE_INDIVIDUAL"
	PartnerApplymentSubjectTypeEnterprise = "SUBJECT_TYPE_ENTERPRISE"
)

type PartnerApplymentIDType string

// PartnerApplymentIDCard 中国大陆居民-身份证
const PartnerApplymentIDCard = "IDENTIFICATION_TYPE_IDCARD"

type PartnerApplymentReq struct {
	BusinessCode string `json:"business_code"`
	ContactInfo  struct {
		ContactName     string `json:"contact_name"`
		ContactIdNumber string `json:"contact_id_number,omitempty"`
		OpenId          string `json:"open_id,omitempty"`
		MobilePhone     string `json:"mobile_phone"`
		ContactEmail    string `json:"contact_email"`
	} `json:"contact_info"`
	SubjectInfo struct {
		SubjectType         PartnerApplymentSubjectType `json:"subject_type"`
		BusinessLicenseInfo struct {
			LicenseCopy   string `json:"license_copy"`
			LicenseNumber string `json:"license_number"`
			MerchantName  string `json:"merchant_name"`
			LegalPerson   string `json:"legal_person"`
		} `json:"business_license_info,omitempty"`
		IdentityInfo struct {
			IdDocType  PartnerApplymentIDType `json:"id_doc_type"`
			Owner      bool                   `json:"owner"`
			IdCardInfo struct {
				IdCardCopy      string `json:"id_card_copy"`
				IdCardNational  string `json:"id_card_national"`
				IdCardName      string `json:"id_card_name"`
				IdCardNumber    string `json:"id_card_number"`
				CardPeriodBegin string `json:"card_period_begin"`
				CardPeriodEnd   string `json:"card_period_end"`
			} `json:"id_card_info"`
		} `json:"identity_info"`
	} `json:"subject_info"`
	BusinessInfo struct {
		MerchantShortname string `json:"merchant_shortname"`
		ServicePhone      string `json:"service_phone"`
		SalesInfo         struct {
			SalesScenesType []string `json:"sales_scenes_type"`
			BizStoreInfo    struct {
				BizStoreName     string   `json:"biz_store_name"`
				BizAddressCode   string   `json:"biz_address_code"`
				BizStoreAddress  string   `json:"biz_store_address"`
				StoreEntrancePic []string `json:"store_entrance_pic"`
				IndoorPic        []string `json:"indoor_pic"`
				BizSubAppid      string   `json:"biz_sub_appid,omitempty"`
			} `json:"biz_store_info"`
		} `json:"sales_info"`
	} `json:"business_info"`
	SettlementInfo struct {
		SettlementId   string   `json:"settlement_id"`
		SettlementType string   `json:"settlement_type"`
		Qualifications []string `json:"qualifications,omitempty"`
	} `json:"settlement_info"`
	BankAccountInfo struct {
		BankAccountType string `json:"bank_account_type"`
		AccountName     string `json:"account_name"`
		AccountBank     string `json:"account_bank"`
		BankAddressCode string `json:"bank_address_code"`
		BankBranchId    string `json:"bank_branch_id,omitempty"`
		BankName        string `json:"bank_name,omitempty"`
		AccountNumber   string `json:"account_number"`
	} `json:"bank_account_info"`
	AdditionInfo struct {
		BusinessAdditionPics []string `json:"business_addition_pics"`
	} `json:"addition_info,omitempty"`
}

type PartnerApplymentResp struct {
	ApplymentId uint64 `json:"applyment_id"`
}

type PartnerApplymentState string

const (
	PartnerApplymentStateEditing   = "APPLYMENT_STATE_EDITTING"
	PartnerApplymentStateAuditing  = "APPLYMENT_STATE_AUDITING"
	PartnerApplymentStateRejected  = "APPLYMENT_STATE_REJECTED"
	PartnerApplymentStateBeConfirm = "APPLYMENT_STATE_TO_BE_CONFIRMED"
	PartnerApplymentStateBeSigned  = "APPLYMENT_STATE_TO_BE_SIGNED"
	PartnerApplymentStateSigning   = "APPLYMENT_STATE_SIGNING"
	PartnerApplymentStateFinished  = "APPLYMENT_STATE_FINISHED"
	PartnerApplymentStateCanceled  = "APPLYMENT_STATE_CANCELED"
)

type PartnerApplymentQueryResp struct {
	BusinessCode      string                `json:"business_code"`
	ApplymentId       uint64                `json:"applyment_id"`
	SubMchid          string                `json:"sub_mchid,omitempty"`
	SignUrl           string                `json:"sign_url,omitempty"`
	ApplymentState    PartnerApplymentState `json:"applyment_state"`
	ApplymentStateMsg string                `json:"applyment_state_msg"`
	AuditDetail       []struct {
		Field       string `json:"field"`
		FieldName   string `json:"field_name"`
		FieldReason string `json:"field_reason"`
	} `json:"audit_detail,omitempty"`
}
