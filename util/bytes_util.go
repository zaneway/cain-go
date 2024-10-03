package util

import (
	"encoding/base64"
	"encoding/hex"
	"strconv"
)

func Base64EncodeToString(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func Base64DecodeFromString(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

func HexEncodeBytesToString(data []byte) string {
	return hex.EncodeToString(data)
}

func HexEncodeIntToString(data int) string {
	return strconv.FormatInt(int64(data), 16)
}

func HexDecodeStringToBytes(data string) ([]byte, error) {
	return hex.DecodeString(data)
}

func HexDecodeStringToInt(data string) (int, error) {
	i, err := strconv.ParseInt(data, 16, 64)
	return int(i), err
}
