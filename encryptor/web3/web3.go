package web3

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/dynamicgo/xerrors"
	"github.com/openzknetwork/sha3"
	"github.com/pborman/uuid"

	"github.com/openzknetwork/key"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

var (
	standardScryptN = 1 << 18
	standardScryptP = 1
	lightScryptN    = 1 << 12
	lightScryptP    = 6
	scryptR         = 8
	scryptDklen     = 32
	scryptKDFName   = "scrypt"
	pbkdf2Name      = "pbkdf2"
)

// Errors
var (
	ErrDecrypt = errors.New("could not decrypt key with given passphrase")
)

// KdfParams .
type KdfParams struct {
	DkLen int    `json:"dklen"` // DK length
	Salt  string `json:"salt"`  // salt string
}

type encryptedKeyJSONV3 struct {
	Address string     `json:"address"`
	Crypto  cryptoJSON `json:"crypto"`
	ID      string     `json:"id"`
	Version int        `json:"version"`
}

type cryptoJSON struct {
	Cipher       string                 `json:"cipher"`
	CipherText   string                 `json:"ciphertext"`
	CipherParams cipherparamsJSON       `json:"cipherparams"`
	KDF          string                 `json:"kdf"`
	KDFParams    map[string]interface{} `json:"kdfparams"`
	MAC          string                 `json:"mac"`
}

type cipherparamsJSON struct {
	IV string `json:"iv"`
}

type encodingImpl struct {
	scryptN int
	scryptP int
}

func (encoding *encodingImpl) Name() string {
	return "web3"
}

// GetEntropyCSPRNG .
func getEntropyCSPRNG(n int) []byte {
	mainBuff := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, mainBuff)
	if err != nil {
		panic("reading from crypto/rand failed: " + err.Error())
	}
	return mainBuff
}

func (encoding *encodingImpl) Encrypt(key key.Key, attrs key.Property, writer io.Writer) error {

	password := attrs["password"]

	authArray := []byte(password)
	salt := getEntropyCSPRNG(32)

	derivedKey, err := scrypt.Key(authArray, salt, encoding.scryptN, scryptR, encoding.scryptP, scryptDklen)

	if err != nil {
		return err
	}

	encryptKey := derivedKey[:16]

	keyBytes := key.PriKey()

	if len(keyBytes) < 32 {
		keyBytes := make([]byte, 32)

		copy(keyBytes, key.PriKey())
	}

	iv := getEntropyCSPRNG(aes.BlockSize) // 16

	cipherText, err := aesCTRXOR(encryptKey, keyBytes, iv)
	if err != nil {
		return err
	}

	hasher := sha3.NewKeccak256()

	hasher.Write(derivedKey[16:32])
	hasher.Write(cipherText)

	mac := hasher.Sum(nil)

	scryptParamsJSON := make(map[string]interface{}, 5)
	scryptParamsJSON["n"] = encoding.scryptN
	scryptParamsJSON["r"] = scryptR
	scryptParamsJSON["p"] = encoding.scryptP
	scryptParamsJSON["dklen"] = scryptDklen
	scryptParamsJSON["salt"] = hex.EncodeToString(salt)

	cipherParamsJSON := cipherparamsJSON{
		IV: hex.EncodeToString(iv),
	}

	cryptoStruct := cryptoJSON{
		Cipher:       "aes-128-ctr",
		CipherText:   hex.EncodeToString(cipherText),
		CipherParams: cipherParamsJSON,
		KDF:          scryptKDFName,
		KDFParams:    scryptParamsJSON,
		MAC:          hex.EncodeToString(mac),
	}
	encryptedKeyJSONV3 := encryptedKeyJSONV3{
		key.Address(),
		cryptoStruct,
		uuid.New(),
		3,
	}
	buff, err := json.Marshal(encryptedKeyJSONV3)

	if err != nil {
		return xerrors.Wrapf(err, "marshal encryptedKeyJSONV3 error")
	}

	_, err = writer.Write(buff)

	if err != nil {
		return xerrors.Wrapf(err, "write encryptedKeyJSONV3 error")
	}

	return nil
}

func (encoding *encodingImpl) Decrypt(key key.Key, attrs key.Property, reader io.Reader) error {

	password := attrs["password"]

	data, err := ioutil.ReadAll(reader)

	if err != nil {
		return xerrors.Wrapf(err, "read all data from reader err")
	}

	// Parse the json into a simple map to fetch the key version
	kv := make(map[string]interface{})
	if err := json.Unmarshal(data, &kv); err != nil {
		return xerrors.Wrapf(err, "unmarshal kv error")
	}

	if version, ok := kv["version"].(string); ok && version != "3" {
		return xerrors.Errorf("cryptox library only support keystore version 3")
	}

	k := new(encryptedKeyJSONV3)

	if err := json.Unmarshal(data, k); err != nil {
		return xerrors.Wrapf(err, "unmarshal encryptedKeyJSONV3 error")
	}

	keyBytes, _, err := encoding.decryptKeyV3(k, password)

	if err != nil {
		return err
	}

	key.SetBytes(keyBytes)

	return nil
}

func (encoding *encodingImpl) decryptKeyV3(
	keyProtected *encryptedKeyJSONV3,
	password string) (keyBytes []byte, keyID []byte, err error) {

	if keyProtected.Crypto.Cipher != "aes-128-ctr" {
		return nil, nil, xerrors.Errorf("Cipher not supported: %v", keyProtected.Crypto.Cipher)
	}

	keyID = uuid.Parse(keyProtected.ID)
	mac, err := hex.DecodeString(keyProtected.Crypto.MAC)

	if err != nil {
		return nil, nil, xerrors.Wrapf(err, "decode keyProtected.Crypto.MAC error")
	}

	iv, err := hex.DecodeString(keyProtected.Crypto.CipherParams.IV)
	if err != nil {
		return nil, nil, xerrors.Wrapf(err, "decode keyProtected.Crypto.CipherParams.IV error")
	}

	cipherText, err := hex.DecodeString(keyProtected.Crypto.CipherText)
	if err != nil {
		return nil, nil, xerrors.Wrapf(err, "decode keyProtected.Crypto.CipherTextC error")
	}

	derivedKey, err := getKDFKey(keyProtected.Crypto, password)
	if err != nil {
		return nil, nil, xerrors.Wrapf(err, "getKDFKey error")
	}

	hasher := sha3.NewKeccak256()

	hasher.Write(derivedKey[16:32])
	hasher.Write(cipherText)

	calculatedMAC := hasher.Sum(nil)

	if !bytes.Equal(calculatedMAC, mac) {
		return nil, nil, xerrors.Errorf("%s\n%s\n%s",
			ErrDecrypt,
			hex.EncodeToString(calculatedMAC),
			hex.EncodeToString(mac))
	}

	plainText, err := aesCTRXOR(derivedKey[:16], cipherText, iv)

	if err != nil {
		return nil, nil, err
	}

	return plainText, keyID, err
}

func aesCTRXOR(key, inText, iv []byte) ([]byte, error) {
	// AES-128 is selected due to size of encryptKey.
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(aesBlock, iv)
	outText := make([]byte, len(inText))
	stream.XORKeyStream(outText, inText)
	return outText, err
}

func ensureInt(x interface{}) int {
	res, ok := x.(int)
	if !ok {
		res = int(x.(float64))
	}
	return res
}

func getKDFKey(cryptoJSON cryptoJSON, auth string) ([]byte, error) {
	authArray := []byte(auth)
	salt, err := hex.DecodeString(cryptoJSON.KDFParams["salt"].(string))
	if err != nil {
		return nil, err
	}
	dkLen := ensureInt(cryptoJSON.KDFParams["dklen"])

	if cryptoJSON.KDF == scryptKDFName {
		n := ensureInt(cryptoJSON.KDFParams["n"])
		r := ensureInt(cryptoJSON.KDFParams["r"])
		p := ensureInt(cryptoJSON.KDFParams["p"])
		return scrypt.Key(authArray, salt, n, r, p, dkLen)

	} else if cryptoJSON.KDF == "pbkdf2" {
		c := ensureInt(cryptoJSON.KDFParams["c"])
		prf := cryptoJSON.KDFParams["prf"].(string)
		if prf != "hmac-sha256" {
			return nil, fmt.Errorf("Unsupported PBKDF2 PRF: %s", prf)
		}
		key := pbkdf2.Key(authArray, salt, c, dkLen, sha256.New)
		return key, nil
	}

	return nil, fmt.Errorf("Unsupported KDF: %s", cryptoJSON.KDF)
}

func init() {
	key.RegisterEncryptor("web3.light", &encodingImpl{scryptN: lightScryptN, scryptP: lightScryptP})
	key.RegisterEncryptor("web3.standard", &encodingImpl{scryptN: standardScryptN, scryptP: standardScryptP})
}
