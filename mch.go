package wxApi

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"strconv"
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

// 微信下单请求
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
	ProfitSharing  string   `xml:"profit_sharing"`
}

// 微信下单结果
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

// 微信下单
func (m Mch) Order(req OrderReq) (rs OrderRes, err error) {
	api := "https://api.mch.weixin.qq.com/pay/unifiedorder"
	if req.ProfitSharing == "" {
		req.ProfitSharing = "N"
	}
	req.Sign = m.sign(req)
	buf := new(bytes.Buffer)
	if err = xml.NewEncoder(buf).Encode(req); err != nil {
		return
	}
	res, err := http.Post(api, "", buf)
	if err != nil {
		return
	}
	err = xml.NewDecoder(res.Body).Decode(&rs)
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

// 支付成功通知
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

type NotifyRes struct {
	XMLName    xml.Name `xml:"xml"`
	ReturnCode string   `xml:"return_code"`
	ReturnMsg  string   `xml:"return_msg"`
}

// 验证支付成功通知
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

// 支付结果查询请求
type OrderQueryRes struct {
	mchErr
	AppId          string `xml:"appid"`
	MchId          string `xml:"mch_id"`
	NonceStr       string `xml:"nonce_str"`
	Sign           string `xml:"sign"`
	Openid         string `xml:"openid"`
	IsSubscribe    string `xml:"is_subscribe"`
	TradeType      string `xml:"trade_type"`
	TradeState     string `xml:"trade_state"`
	BankType       string `xml:"bank_type"`
	TotalFee       int64  `xml:"total_fee"`
	CashFee        int64  `xml:"cash_fee"`
	TransactionId  string `xml:"transaction_id"`
	OutTradeNo     string `xml:"out_trade_no"`
	Attach         string `xml:"attach"`
	TimeEnd        string `xml:"time_end"`
	TradeStateDesc string `xml:"trade_state_desc"`
}

func (rs OrderQueryRes) String() string {
	raw, _ := json.Marshal(rs)
	return string(raw)
}

// 支付结果查询
func (m Mch) OrderQuery(appId, outTradeNo string) (rs OrderQueryRes, err error) {
	api := "https://api.mch.weixin.qq.com/pay/orderquery"
	var req = struct {
		XMLName    xml.Name `xml:"xml"`
		AppId      string   `xml:"appid"`
		MchId      string   `xml:"mch_id"`
		OutTradeNo string   `xml:"out_trade_no"`
		NonceStr   string   `xml:"nonce_str"`
		Sign       string   `xml:"sign"`
	}{
		AppId:      appId,
		MchId:      m.MchId,
		OutTradeNo: outTradeNo,
		NonceStr:   NewRandStr(32),
	}
	req.Sign = m.sign(req)
	buf := new(bytes.Buffer)
	if err = xml.NewEncoder(buf).Encode(req); err != nil {
		return
	}
	res, err := http.Post(api, "", buf)
	if err != nil {
		return
	}
	if err = xml.NewDecoder(res.Body).Decode(&rs); err != nil {
		return
	}
	return
}

// 单次分账结果
type ProfitSharingReq struct {
	XMLName       xml.Name                   `xml:"xml"`
	MchId         string                     `xml:"mch_id"`
	AppId         string                     `xml:"appid"`
	NonceStr      string                     `xml:"nonce_str"`
	Sign          string                     `xml:"sign"`
	TransactionId string                     `xml:"transaction_id"`
	OutOrderNo    string                     `xml:"out_order_no"`
	Receivers     string                     `xml:"receivers"`
	ReceiverSlice []ProfitSharingReqReceiver `xml:"-"`
}

// 分账结果中的接收者
type ProfitSharingReqReceiver struct {
	Type        string `json:"type"`
	Account     string `json:"account"`
	Amount      int64  `json:"amount"`
	Description string `json:"description"`
}

// 单次分账结果
type ProfitSharingRes struct {
	mchErr
	MchId         string `xml:"mch_id"`
	AppId         string `xml:"appid"`
	NonceStr      string `xml:"nonce_str"`
	Sign          string `xml:"sign"`
	TransactionId string `xml:"transaction_id"`
	OutOrderNo    string `xml:"out_order_no"`
	OrderId       string `xml:"order_id"`
}

func (r ProfitSharingRes) String() string {
	raw, _ := json.Marshal(r)
	return string(raw)
}

// 请求单次分账
func (m Mch) ProfitSharing(req ProfitSharingReq) (rs ProfitSharingRes, err error) {
	if err = m.prepareCert(); err != nil {
		return
	}
	if len(req.ReceiverSlice) == 0 {
		err = errors.New("接收方列表不能为空")
		return
	}
	raw, err := json.Marshal(req.ReceiverSlice)
	if err != nil {
		return
	}

	req.Receivers = string(raw)
	req.MchId = m.MchId
	req.Sign = m.payHmacSha256Sign(req)

	buf := new(bytes.Buffer)
	if err = xml.NewEncoder(buf).Encode(req); err != nil {
		return
	}

	api := "https://api.mch.weixin.qq.com/secapi/pay/profitsharing"
	body, err := postStreamWithCert(*m.mchCert, api, buf)
	if err != nil {
		return
	}
	err = xml.NewDecoder(body).Decode(&rs)
	return
}

// 结束分账请求
type ProfitSharingFinishReq struct {
	XMLName       xml.Name `xml:"xml"`
	MchId         string   `xml:"mch_id"`
	AppId         string   `xml:"appid"`
	NonceStr      string   `xml:"nonce_str"`
	Sign          string   `xml:"sign"`
	TransactionId string   `xml:"transaction_id"`
	OutOrderNo    string   `xml:"out_order_no"`
	Description   string   `xml:"description"`
}

// 确定分账
func (m Mch) ProfitSharingFinish(req ProfitSharingFinishReq) (rs ProfitSharingRes, err error) {
	if err = m.prepareCert(); err != nil {
		return
	}
	req.MchId = m.MchId
	req.Sign = m.payHmacSha256Sign(req)

	buf := new(bytes.Buffer)
	if err = xml.NewEncoder(buf).Encode(req); err != nil {
		return
	}

	api := "https://api.mch.weixin.qq.com/secapi/pay/profitsharingfinish"
	body, err := postStreamWithCert(*m.mchCert, api, buf)
	if err != nil {
		return
	}
	err = xml.NewDecoder(body).Decode(&rs)
	return
}

// 企业付款到银行卡请求
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

// 企业付款到银行卡结果
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

// 企业付款到银行卡预加密实名与银行卡号
func (m Mch) BankPayReqEncrypt(bpr *BankPayReq) (err error) {
	bpr.EncBankNo, err = rsaEncrypt(m.MchRSAPublicKey, bpr.EncBankNo)
	if err != nil {
		return
	}
	bpr.EncTrueName, err = rsaEncrypt(m.MchRSAPublicKey, bpr.EncTrueName)
	return
}

// 企业付款到银行卡
func (m Mch) BankPay(bpr BankPayReq) (rs BankPayRes, err error) {
	if err = m.prepareCert(); err != nil {
		return
	}
	api := "https://api.mch.weixin.qq.com/mmpaysptrans/pay_bank"
	bpr.Sign = m.sign(bpr)
	buf := new(bytes.Buffer)
	if err = xml.NewEncoder(buf).Encode(bpr); err != nil {
		return
	}
	body, err := postStreamWithCert(*m.mchCert, api, buf)
	if err != nil {
		return
	}
	err = xml.NewDecoder(body).Decode(&rs)
	return
}

// 付款到银行卡结果查询请求
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

// 付款到银行卡结果查询
func (m Mch) BankQuery(tradeNo string) (rs BankQueryRes, err error) {
	if err = m.prepareCert(); err != nil {
		return
	}
	api := "https://api.mch.weixin.qq.com/mmpaysptrans/query_bank"
	var req = struct {
		XMLName        xml.Name `xml:"xml"`
		MchId          string   `xml:"mch_id"`
		PartnerTradeNo string   `xml:"partner_trade_no"`
		NonceStr       string   `xml:"nonce_str"`
		Sign           string   `xml:"sign"`
	}{
		MchId:          m.MchId,
		PartnerTradeNo: tradeNo,
		NonceStr:       NewRandStr(32),
	}
	req.Sign = m.sign(req)
	buf := new(bytes.Buffer)
	if err = xml.NewEncoder(buf).Encode(req); err != nil {
		return
	}
	body, err := postStreamWithCert(*m.mchCert, api, buf)
	if err != nil {
		return
	}
	if err = xml.NewDecoder(body).Decode(&rs); err != nil {
		return
	}
	return
}

// 发红包请求
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

// 发红包结果
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

// 发红包
func (m Mch) SendRedPack(req RedPackReq) (rs RedPackSendRes, err error) {
	err = m.prepareCert()
	if err != nil {
		return
	}
	api := "https://api.mch.weixin.qq.com/mmpaymkttransfers/sendredpack"
	req.MchId = m.MchId
	req.NonceStr = NewRandStr(32)
	req.Sign = m.sign(req)
	var buf = new(bytes.Buffer)
	if err = xml.NewEncoder(buf).Encode(req); err != nil {
		return
	}
	resp, err := postWithCert(*m.mchCert, api, buf)
	if err != nil {
		return
	}
	if err = xml.NewDecoder(resp.Body).Decode(&rs); err != nil {
		return
	}
	return
}

// 红包状态查询请求
type RedPackQueryReq struct {
	XMLName   xml.Name `xml:"xml"`
	NonceStr  string   `xml:"nonce_str"`
	Sign      string   `xml:"sign"`
	MchBillNo string   `xml:"mch_billno"`
	MchId     string   `xml:"mch_id"`
	AppId     string   `xml:"appid"`
	BillType  string   `xml:"bill_type"`
}

// 红包状态查询结果
type RedPackQueryRes struct {
	mchErr
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

func (res RedPackQueryRes) String() string {
	raw, _ := json.Marshal(res)
	return string(raw)
}

// 红包状态查询
func (m Mch) RedPackQuery(req RedPackQueryReq) (rs RedPackQueryRes, err error) {
	if err = m.prepareCert(); err != nil {
		return
	}
	api := "https://api.mch.weixin.qq.com/mmpaymkttransfers/gethbinfo"
	req.MchId = m.MchId
	req.NonceStr = NewRandStr(32)
	req.Sign = m.sign(req)
	var buf = new(bytes.Buffer)
	if err = xml.NewEncoder(buf).Encode(req); err != nil {
		return
	}
	resp, err := postWithCert(*m.mchCert, api, buf)
	if err != nil {
		return
	}
	err = xml.NewDecoder(resp.Body).Decode(&rs)
	return
}

// 企业付款至零钱请求
type PayReq struct {
	XMLName        xml.Name `xml:"xml"`
	MchAppId       string   `xml:"mch_appid"`
	MchId          string   `xml:"mchid"`
	NonceStr       string   `xml:"nonce_str"`
	Sign           string   `xml:"sign"`
	PartnerTradeNo string   `xml:"partner_trade_no"`
	OpenId         string   `xml:"openid"`
	CheckName      string   `xml:"check_name"`
	ReUserName     string   `xml:"re_user_name"`
	Amount         int      `xml:"amount"`
	Desc           string   `xml:"desc"`
	SpBillCreateIp string   `xml:"spbill_create_ip"`
}

// 企业付款至零钱结果
type PayRes struct {
	mchErr
	MchAppId       string `xml:"mch_appid"`
	MchId          string `xml:"mchid"`
	NonceStr       string `xml:"nonce_str"`
	PartnerTradeNo string `xml:"partner_trade_no"`
	PaymentNo      string `xml:"payment_no"`
	PaymentTime    string `xml:"payment_time"`
}

func (res PayRes) String() string {
	raw, _ := json.Marshal(res)
	return string(raw)
}

// 企业付款至零钱
func (m Mch) Pay(req PayReq) (rs PayRes, err error) {
	err = m.prepareCert()
	if err != nil {
		return
	}
	api := "https://api.mch.weixin.qq.com/mmpaymkttransfers/promotion/transfers"
	req.MchId = m.MchId
	req.NonceStr = NewRandStr(32)
	req.Sign = m.sign(req)

	var buf = new(bytes.Buffer)
	if err = xml.NewEncoder(buf).Encode(req); err != nil {
		return
	}
	resp, err := postWithCert(*m.mchCert, api, buf)
	if err != nil {
		return
	}
	if err = xml.NewDecoder(resp.Body).Decode(&rs); err != nil {
		return
	}
	return
}

// 退款请求
type RefundReq struct {
	XMLName       xml.Name `xml:"xml"`
	AppId         string   `xml:"appid"`
	MchId         string   `xml:"mch_id"`
	NonceStr      string   `xml:"nonce_str"`
	Sign          string   `xml:"sign"`
	TransactionId string   `xml:"transaction_id"`
	OutTradeNo    string   `xml:"out_trade_no"`
	OutRefundNo   string   `xml:"out_refund_no"`
	TotalFee      int64    `xml:"total_fee"`
	RefundFee     int64    `xml:"refund_fee"`
	RefundDesc    string   `xml:"refund_desc"`
	NotifyUrl     string   `xml:"notify_url"`
}

// 退款结果
type RefundRes struct {
	mchErr
	AppId         string `xml:"appid"`
	MchId         string `xml:"mch_id"`
	NonceStr      string `xml:"nonce_str"`
	Sign          string `xml:"sign"`
	TransactionId string `xml:"transaction_id"`
	OutTradeNo    string `xml:"out_trade_no"`
	OutRefundNo   string `xml:"out_refund_no"`
	RefundId      string `xml:"refund_id"`
	RefundFee     int64  `xml:"refund_fee"`
	TotalFee      int64  `xml:"total_fee"`
	CashFee       int64  `xml:"cash_fee"`
}

// 退款
func (m Mch) Refund(req RefundReq) (rs RefundRes, err error) {
	if err = m.prepareCert(); err != nil {
		return
	}
	api := "https://api.mch.weixin.qq.com/secapi/pay/refund"
	req.MchId = m.MchId
	req.NonceStr = NewRandStr(32)
	req.Sign = m.sign(req)
	var buf = new(bytes.Buffer)
	if err = xml.NewEncoder(buf).Encode(req); err != nil {
		return
	}
	body, err := postStreamWithCert(*m.mchCert, api, buf)
	if err != nil {
		return
	}
	if err = xml.NewDecoder(body).Decode(&rs); err != nil {
		return
	}
	return
}

// 获取RSA公钥API获取RSA公钥请求
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

// 获取RSA公钥API获取RSA公钥
func (m Mch) GetBankRSAPublicKey() (rs BankRSARes, err error) {
	if err = m.prepareCert(); err != nil {
		return
	}

	var data = struct {
		XMLName  xml.Name `xml:"xml"`
		MchId    string   `xml:"mch_id"`
		NonceStr string   `xml:"nonce_str"`
		SignType string   `xml:"sign_type"`
		Sign     string   `xml:"sign"`
	}{
		MchId:    m.MchId,
		NonceStr: NewRandStr(32),
		SignType: "MD5",
	}
	data.Sign = m.sign(data)
	buf := new(bytes.Buffer)
	if err = xml.NewEncoder(buf).Encode(data); err != nil {
		return
	}

	body, err := postStreamWithCert(*m.mchCert, "https://fraud.mch.weixin.qq.com/risk/getpublickey", buf)
	if err != nil {
		return
	}
	if err = xml.NewDecoder(body).Decode(&rs); err != nil {
		return
	}

	return
}

func (m Mch) sign(obj interface{}) (sign string) {
	sign = fmt.Sprintf("%X", md5.Sum([]byte(mapSortByKey(obj2map(obj))+"&key="+m.MchKey)))
	return
}

func (m Mch) paySign(data map[string]interface{}) string {
	return fmt.Sprintf("%X", md5.Sum([]byte(mapSortByKey(data)+"&key="+m.MchKey)))
}

func (m Mch) payHmacSha256Sign(obj interface{}) string {
	hm := hmac.New(sha256.New, []byte(m.MchKey))
	hm.Write([]byte(mapSortByKey(obj2map(obj)) + "&key=" + m.MchKey))
	return fmt.Sprintf("%X", hm.Sum(nil))
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
