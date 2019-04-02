package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/openzknetwork/key"
	_ "github.com/openzknetwork/key/encryptor"
	_ "github.com/openzknetwork/key/provider"
)

func main() {
	buff, err := ioutil.ReadFile(os.Args[1])

	if err != nil {
		println(fmt.Sprintf("load keystore from `%s` err: \n\t%s", os.Args[1], err))
		return
	}

	k, err := key.New("neo")

	if err != nil {
		println(fmt.Sprintf("err: %s", err))
		return
	}

	err = key.Decrypt("web3.standard", k, map[string]string{
		"password": os.Args[2],
	}, bytes.NewBuffer(buff))

	if err != nil {
		println(fmt.Sprintf("err: %s", err))
		return
	}

	var buff2 bytes.Buffer

	err = key.Encrypt("wif.neo", k, nil, &buff2)

	if err != nil {
		println(fmt.Sprintf("err: %s", err))
		return
	}

	println(fmt.Sprintf("wif: %s", buff2.String()))
}
