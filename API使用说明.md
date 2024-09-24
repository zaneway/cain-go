# 国密GM/T Go API使用说明

<!-- TOC -->

- [国密GM/T Go API使用说明](#国密gmt-go-api使用说明)
    - [Go包安装](#go包安装)
    - [SM2椭圆曲线公钥密码算法](#sm2椭圆曲线公钥密码算法)
        - [代码示例](#代码示例)
    - [SM3密码杂凑算法](#sm3密码杂凑算法)
        - [代码示例](#代码示例-1)
    - [SM4分组密码算法](#sm4分组密码算法)
        - [代码示例](#代码示例-2)
    - [相关代码示例参考](#相关代码示例参考)
    - [国密SSL（TLCP）](#国密ssltlcp)

<!-- /TOC -->

## Go包安装

```bash
go get -u cain-go
```
## SM2椭圆曲线公钥密码算法

>   SM2椭圆曲线公钥密码算法 Public key cryptographic algorithm SM2 based on elliptic curves

- 遵循的SM2标准号为： GM/T 0003.1-2012、GM/T 0003.2-2012、GM/T 0003.3-2012、GM/T 0003.4-2012、GM/T 0003.5-2012、GM/T 0009-2012、GM/T 0010-2012
- go package： `cain-go/sm2`

### 代码示例

```Go
    priv, err := sm2.GenerateKey(rand.Reader) // 生成密钥对
    if err != nil {
    	log.Fatal(err)
    }
    msg := []byte("Tongji Fintech Research Institute")
    pub := &priv.PublicKey
    ciphertxt, err := pub.EncryptAsn1(msg,rand.Reader) //sm2加密
    if err != nil {
    	log.Fatal(err)
    }
    fmt.Printf("加密结果:%x\n",ciphertxt)
    plaintxt,err :=  priv.DecryptAsn1(ciphertxt)  //sm2解密
    if err != nil {
    	log.Fatal(err)
    }
    if !bytes.Equal(msg,plaintxt){
        log.Fatal("原文不匹配")
    }

   sign,err := priv.Sign(rand.Reader, msg, nil)  //sm2签名
    if err != nil {
    	log.Fatal(err)
    }
    isok := pub.Verify(msg, sign)    //sm2验签
    fmt.Printf("Verified: %v\n", isok)
```
## SM3密码杂凑算法

> SM3密码杂凑算法 - SM3 cryptographic hash algorithm

- 遵循的SM3标准号为： GM/T 0004-2012
- g package：`cain-go/sm3`
- `type SM3 struct` 是原生接口hash.Hash的一个实现

### 代码示例

```Go
    data := "test"
    h := sm3.New()
    h.Write([]byte(data))
    sum := h.Sum(nil)
    fmt.Printf("digest value is: %x\n",sum)
```

## SM4分组密码算法

> SM4分组密码算法 - SM4 block cipher algorithm

- 遵循的SM4标准号为:  GM/T 0002-2012
- go package：`cain-go/sm4`

### 代码示例

```Go
    import  "crypto/cipher"
    import  "github.com/zaneway/cain-go/sm4"
    import "fmt"

    func main(){
    key := []byte("1234567890abcdef")
	fmt.Printf("key = %v\n", key)
	data := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	fmt.Printf("key = %v\n", key)
	fmt.Printf("data = %x\n", data)
    iv := []byte("0000000000000000")
	err = SetIV(iv)//设置SM4算法实现的IV值,不设置则使用默认值
	ecbMsg, err :=sm4.Sm4Ecb(key, data, true)   //sm4Ecb模式pksc7填充加密
	if err != nil {
		t.Errorf("sm4 enc error:%s", err)
		return
	}
	fmt.Printf("ecbMsg = %x\n", ecbMsg)
	ecbDec, err := sm4.Sm4Ecb(key, ecbMsg, false)  //sm4Ecb模式pksc7填充解密
	if err != nil {
		t.Errorf("sm4 dec error:%s", err)
		return
	}
	fmt.Printf("ecbDec = %x\n", ecbDec)
    }
```


## 相关代码示例参考

- [SM2算法 sm2/sm2_test.go](sm2/sm2_test.go)
- [SM3算法 sm3/sm3_test.go](sm3/sm3_test.go)
- [SM4算法 sm4/sm4_test.go](sm4/sm4_test.go)
- [x509国密证书 x509/x509_test.go](x509/x509_test.go)
