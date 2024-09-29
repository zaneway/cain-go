
# cain
GM SM2/3/4 library based on Golang
=======



## Feature
 cain包含以下主要功能

    SM2: 国密椭圆曲线算法库
        . 支持Generate Key, Sign, Verify基础操作
        . 支持加密和不加密的pem文件格式(加密方法参见RFC5958, 具体实现参加代码)
        . 支持证书的生成，证书的读写(接口兼容rsa和ecdsa的证书)
        . 支持证书链的操作(接口兼容rsa和ecdsa)
        . 支持crypto.Signer接口

    SM3: 国密hash算法库
       . 支持基础的sm3Sum操作
       . 支持hash.Hash接口

    SM4: 国密分组密码算法库
        . 支持Generate Key, Encrypt, Decrypt基础操作
        . 提供Cipher.Block接口
        . 支持加密和不加密的pem文件格式(加密方法为pem block加密, 具体函数为x509.EncryptPEMBlock)

## Usage 使用说明

```go
go get github.com/zaneway/cain-go@v1.0.0
```

 ## [License](./LICENSE)

## Future
工具化：asn1结构方向完善




