package main

import (
	"crypto"
	"log"
	"testing"
)

func TestSign(t *testing.T) {
	PRIVATE_KEY, _ := ReadFromKey("private.key")
	PUBLIC_KEY, _ := ReadFromKey("public.key")

	//原内容
	str := "我是orderNumber"
	//生成签名
	sig := RSASign(str, PRIVATE_KEY, crypto.SHA256)
	log.Println(sig)
	//验证原内容与签名是否一致

	res := RSAPubCheckSign(str, sig, PUBLIC_KEY, crypto.SHA256)
	log.Println(res)
}

//func TestGenrateKey(t *testing.T) {
//	//生成密钥对，保存到文件
//	GenerateRSAKey(2048)
//}
