package wxApi

import (
	"log"
	"testing"
	"unicode/utf8"
)

func TestSafeString(t *testing.T) {
	str := "来自[唯τā命゛L]的成交奖励"
	for k, v := range []rune(str) {
		log.Println(k, string(v), utf8.ValidRune(v), len([]byte(string(v))), v)
	}
	log.Println(SafeString(str, 32))
}
