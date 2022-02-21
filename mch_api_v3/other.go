// Copyright 2022 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package mch_api_v3

import "time"

type OtherCertificatesResp struct {
	Data []struct {
		SerialNo           string    `json:"serial_no"`
		EffectiveTime      time.Time `json:"effective_time"`
		ExpireTime         time.Time `json:"expire_time"`
		EncryptCertificate struct {
			Algorithm      string `json:"algorithm"`
			Nonce          string `json:"nonce"`
			AssociatedData string `json:"associated_data"`
			Ciphertext     string `json:"ciphertext"`
		} `json:"encrypt_certificate"`
	} `json:"data"`
}
