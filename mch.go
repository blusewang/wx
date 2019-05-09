package wxApi

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// 商户
type Mch struct {
	MchId           string
	MchName         string
	MchKey          string
	MchSSLCert      []byte
	MchSSLKey       []byte
	mchCert         *tls.Certificate
	MchRSAPublicKey []byte
}

// 微信下单
type OrderReq struct {
	XMLName        xml.Name `xml:"xml"`
	AppId          string   `xml:"appid"`
	MchId          string   `xml:"mch_id"`
	DeviceInfo     string   `xml:"device_info"`
	OpenId         string   `xml:"openid"`
	NonceStr       string   `xml:"nonce_str"`
	Body           string   `xml:"body"`
	OutTradeNo     string   `xml:"out_trade_no"`
	TotalFee       int64    `xml:"total_fee"`
	SpbillCreateIp string   `xml:"spbill_create_ip"`
	NotifyUrl      string   `xml:"notify_url"`
	TradeType      string   `xml:"trade_type"`
	Attach         string   `xml:"attach"`
	Sign           string   `xml:"sign"`
}

type OrderRes struct {
	mchErr
	AppId     string `xml:"appid"`
	MchId     string `xml:"mch_id"`
	NonceStr  string `xml:"nonce_str"`
	Sign      string `xml:"sign"`
	TradeType string `xml:"trade_type"`
	PrepayId  string `xml:"prepay_id"`
}

func (or OrderRes) String() string {
	raw, _ := json.Marshal(or)
	return string(raw)
}

func (m Mch) Order(req OrderReq) (rs OrderRes, err error) {
	api := "https://api.mch.weixin.qq.com/pay/unifiedorder"
	req.Sign = m.sign(req)
	raw, err := xml.Marshal(req)
	if err != nil {
		return
	}
	raw, err = postRaw(api, bytes.NewBuffer(raw), "")
	if err != nil {
		return
	}
	err = parseXml(raw, &rs)
	return
}

// 将订单签名给App
func (m Mch) OrderSign4App(or OrderRes) H {
	data := make(H)
	data["appid"] = or.AppId
	data["partnerid"] = or.MchId
	data["prepayid"] = or.PrepayId
	data["package"] = "Sign=WXPay"
	data["noncestr"] = NewRandStr(32)
	data["timestamp"] = time.Now().Unix()
	data["sign"] = m.paySign(data)
	delete(data, "appid")
	return data
}

// 将订单签名给小程序
func (m Mch) OrderSign4MP(or OrderRes) H {
	data := make(H)
	data["appId"] = or.AppId
	data["timeStamp"] = strconv.FormatInt(time.Now().Unix(), 10)
	data["nonceStr"] = NewRandStr(32)
	data["package"] = fmt.Sprintf("prepay_id=%v", or.PrepayId)
	data["signType"] = "MD5"
	data["paySign"] = m.paySign(data)
	delete(data, "appId")
	return data
}

// 验证回调签名

type PayNotify struct {
	ReturnCode         string `xml:"return_code"`
	ReturnMsg          string `xml:"return_msg"`
	ResultCode         string `xml:"result_code"`
	ErrCode            string `xml:"err_code"`
	ErrCodeDes         string `xml:"err_code_des"`
	AppId              string `xml:"appid"`
	MchId              string `xml:"mch_id"`
	DeviceInfo         string `xml:"device_info"`
	NonceStr           string `xml:"nonce_str"`
	Sign               string `xml:"sign"`
	SignType           string `xml:"sign_type"`
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
	TransactionId      string `xml:"transaction_id"`
	OutTradeNo         string `xml:"out_trade_no"`
	Attach             string `xml:"attach"`
	TimeEnd            string `xml:"time_end"`
}

func (m Mch) PayNotify(pn PayNotify) bool {
	if pn.ReturnCode != "SUCCESS" || pn.Sign == "" {
		return false
	}
	sign := pn.Sign
	if sign != m.sign(pn) {
		return false
	}
	return true
}

// 企业付款到银行卡
type BankPayReq struct {
	XMLName        xml.Name `xml:"xml"`
	MchId          string   `xml:"mch_id"`
	PartnerTradeNo string   `xml:"partner_trade_no"`
	NonceStr       string   `xml:"nonce_str"`
	EncBankNo      string   `xml:"enc_bank_no"`
	EncTrueName    string   `xml:"enc_true_name"`
	BankCode       string   `xml:"bank_code"`
	AmountFen      int64    `xml:"amount"`
	Desc           string   `xml:"desc"`
	Sign           string   `xml:"sign"`
}

func (bpr BankPayReq) String() string {
	raw, _ := json.Marshal(bpr)
	return string(raw)
}

type BankPayRes struct {
	mchErr
	PartnerTradeNo string `xml:"partner_trade_no"`
	AmountFen      int64  `xml:"amount"`
	PaymentNo      string `xml:"payment_no"`
	CMmsAmt        int64  `xml:"cmms_amt"`
}

func (bp BankPayRes) String() string {
	raw, _ := json.Marshal(bp)
	return string(raw)
}
func (m Mch) BankPayReqEncrypt(bpr *BankPayReq) (err error) {
	bpr.EncBankNo, err = rsaEncrypt(m.MchRSAPublicKey, bpr.EncBankNo)
	if err != nil {
		return
	}
	bpr.EncTrueName, err = rsaEncrypt(m.MchRSAPublicKey, bpr.EncTrueName)
	return
}
func (m Mch) BankPay(bpr BankPayReq) (rs BankPayRes, err error) {
	err = m.prepareCert()
	if err != nil {
		return
	}
	api := "https://api.mch.weixin.qq.com/mmpaysptrans/pay_bank"
	bpr.Sign = m.sign(bpr)
	raw, err := xml.Marshal(bpr)
	if err != nil {
		return
	}
	raw, err = postWithCert(*m.mchCert, api, raw)
	if err != nil {
		return
	}
	err = parseXml(raw, &rs)
	return
}

// 发红包
type RedPackReq struct {
	XMLName     xml.Name `xml:"xml"`
	NonceStr    string   `xml:"nonce_str"`
	Sign        string   `xml:"sign"`
	MchBillNo   string   `xml:"mch_billno"`
	MchId       string   `xml:"mch_id"`
	WxAppId     string   `xml:"wxappid"`
	SendName    string   `xml:"send_name"`
	ReOpenId    string   `xml:"re_openid"`
	TotalAmount int      `xml:"total_amount"`
	TotalNum    int      `xml:"total_num"`
	Wishing     string   `xml:"wishing"`
	ClientIp    string   `xml:"client_ip"`
	ActName     string   `xml:"act_name"`
	Remark      string   `xml:"remark"`
}

type RedPackSendRes struct {
	mchErr
	MchBillNo   string `xml:"mch_billno"`
	MchId       string `xml:"mch_id"`
	WxAppId     string `xml:"wxappid"`
	ReOpenId    string `xml:"re_openid"`
	TotalAmount int    `xml:"total_amount"`
	SendListId  string `xml:"send_listid"`
}

func (res RedPackSendRes) String() string {
	raw, _ := json.Marshal(res)
	return string(raw)
}
func (m Mch) SendRedPack(req RedPackReq) (rs RedPackSendRes, err error) {
	err = m.prepareCert()
	if err != nil {
		return
	}
	api := "https://api.mch.weixin.qq.com/mmpaymkttransfers/sendredpack"
	req.MchId = m.MchId
	req.NonceStr = NewRandStr(32)
	req.Sign = m.sign(req)
	raw, err := xml.Marshal(req)
	if err != nil {
		return
	}
	raw, err = postWithCert(*m.mchCert, api, raw)
	if err != nil {
		return
	}
	err = parseXml(raw, &rs)
	return
}

// 用于对商户企业付款到银行卡操作进行结果查询
type BankQueryRes struct {
	mchErr
	PartnerTradeNo string `xml:"partner_trade_no"`
	PaymentNo      string `xml:"payment_no"`
	AmountFen      int64  `xml:"amount"`
	Status         string `xml:"status"`
	CMmsAmtFen     int64  `xml:"cmms_amt"`
	CreateTime     string `xml:"create_time"`
	PaySuccessTime string `xml:"pay_succ_time"`
	Reason         string `xml:"reason"`
}

func (bp BankQueryRes) String() string {
	raw, _ := json.Marshal(bp)
	return string(raw)
}
func (m Mch) BankQuery(tradeNo string) (rs BankQueryRes, err error) {
	err = m.prepareCert()
	if err != nil {
		return
	}
	api := "https://api.mch.weixin.qq.com/mmpaysptrans/query_bank"
	data := make(H)
	data["mch_id"] = m.MchId
	data["partner_trade_no"] = tradeNo
	data["nonce_str"] = NewRandStr(32)
	data["sign"] = m.paySign(data)

	raw, err := postWithCert(*m.mchCert, api, MapToXML(data))
	if err != nil {
		return
	}
	err = parseXml(raw, &rs)
	return
}

// 获取RSA公钥API获取RSA公钥
type BankRSARes struct {
	ReturnCode string `xml:"return_code"`
	ReturnMsg  string `xml:"return_msg"`
	ResultCode string `xml:"result_code"`
	MchId      int64  `xml:"mch_id"`
	PubKey     string `xml:"pub_key"`
}

func (bp BankRSARes) String() string {
	raw, _ := json.Marshal(bp)
	return string(raw)
}
func (m Mch) GetBankRSAPublicKey() (rs BankRSARes, err error) {
	err = m.prepareCert()
	if err != nil {
		return
	}

	data := make(H)
	data["mch_id"] = m.MchId
	data["nonce_str"] = NewRandStr(32)
	data["sign_type"] = "MD5"
	data["sign"] = m.paySign(data)

	raw, err := postWithCert(*m.mchCert, "https://fraud.mch.weixin.qq.com/risk/getpublickey", MapToXML(data))
	if err != nil {
		return
	}
	err = xml.Unmarshal(raw, &rs)
	return
}

func (m Mch) sign(obj interface{}) (sign string) {
	ts := reflect.TypeOf(obj)
	vs := reflect.ValueOf(obj)
	p := make(map[string]interface{})
	n := ts.NumField()
	for i := 0; i < n; i++ {
		k := ts.Field(i).Tag.Get("json")
		if k == "" {
			k = ts.Field(i).Tag.Get("xml")
			if k == "xml" {
				continue
			}
		}
		if k == "sign" {
			continue
		}
		// 跳过空值
		if reflect.Zero(vs.Field(i).Type()).Interface() == vs.Field(i).Interface() {
			continue
		}
		p[k] = vs.Field(i).Interface()
	}

	str := mapSortByKey(p)
	raw := md5.Sum([]byte(str + "&key=" + m.MchKey))
	sign = strings.ToUpper(fmt.Sprintf("%x", raw))
	return
}

func (m Mch) paySign(data map[string]interface{}) string {
	str := mapSortByKey(data)
	bits := md5.Sum([]byte(str + "&key=" + m.MchKey))
	return strings.ToUpper(fmt.Sprintf("%x", bits))
}

func (m *Mch) prepareCert() (err error) {
	if m.mchCert == nil {
		if len(m.MchSSLCert) == 0 || len(m.MchSSLKey) == 0 {
			return errors.New("微信商户证书缺失")
		}
		m.mchCert, err = parseCertificate(m.MchSSLCert, m.MchSSLKey, m.MchId)
	}
	return
}
