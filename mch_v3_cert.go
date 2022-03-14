// Copyright 2022 YBCZ, Inc. All rights reserved.
//
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file in the root of the source
// tree.

package wx

import (
	"crypto/x509"
	"time"
)

type PayCert struct {
	SerialNo      string    `json:"serial_no"`
	EffectiveTime time.Time `json:"effective_time"`
	ExpireTime    time.Time `json:"expire_time"`
	cert          *x509.Certificate
}

type PayCertManager struct {
	certs []PayCert
}

func NewPayCerManager() PayCertManager {
	pcm := PayCertManager{}
	return pcm
}

func (pcm *PayCertManager) GetCert() *x509.Certificate {
	for _, cert := range pcm.certs {
		if cert.ExpireTime.After(time.Now()) {
			return cert.cert
		}
	}
	return nil
}

func (pcm *PayCertManager) GetCertBySerialNo(no string) *x509.Certificate {
	for _, cert := range pcm.certs {
		if cert.SerialNo == no {
			return cert.cert
		}
	}
	return nil
}
func (pcm *PayCertManager) GetSerialNo() string {
	for _, cert := range pcm.certs {
		if cert.ExpireTime.After(time.Now()) {
			return cert.SerialNo
		}
	}
	return ""
}

func (pcm *PayCertManager) IsEmpty() bool {
	return len(pcm.certs) == 0
}

func (pcm *PayCertManager) Add(pc PayCert) {
	pcm.certs = append(pcm.certs, pc)
}
