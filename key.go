package key // import "github.com/openzknetwork/key"

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"

	"github.com/openzknetwork/key/internal/bip32"
	"github.com/openzknetwork/key/internal/ecdsax"
	"github.com/openzknetwork/key/internal/ecies"

	"github.com/openzknetwork/key/internal/bip39"

	"github.com/dynamicgo/xerrors"

	"github.com/dynamicgo/injector"
)

var prefix = "LPT_KEY_"

// Property .
type Property map[string]string

// Errors
var (
	ErrDriver        = errors.New("unknown driver")
	ErrPublicKey     = errors.New("invalid public key")
	ErrCanonicalSign = errors.New("couldn't find a canonical signature")
	ErrRecoverSign   = errors.New("recover error")
)

// Key blockchain key facade
type Key interface {
	Address() string                    // address display string
	PriKey() []byte                     // private key byte array
	PubKey() []byte                     // public key byte array
	SetBytes(priKey []byte)             // set private key bytes
	Sign(hashed []byte) ([]byte, error) // sign the hashed message
	Provider() Provider                 // provider
}

// WithNetID .
type WithNetID interface {
	NetID() byte
	SetNetID(id byte)
	SupportNetID() []byte
}

// Provider the key service provider
type Provider interface {
	Name() string      // driver name
	New() (Key, error) // create new key
	Verify(pubkey []byte, sig []byte, hash []byte) bool
	PublicKeyToAddress(pubkey []byte) (string, error)
	ValidAddress(address string) bool
	PrivateToPublic(privateKey []byte) []byte
	Curve() elliptic.Curve
}

// RecoverableProvider .
type RecoverableProvider interface {
	Provider
	Recover(sig []byte, hash []byte) (pubkey []byte, err error)
}

// Encryptor .
type Encryptor interface {
	Encrypt(key Key, property Property, writer io.Writer) error
	Decrypt(key Key, property Property, reader io.Reader) error
}

// BytesEncryptor .
type BytesEncryptor interface {
	EncryptBytes(source []byte, property Property, writer io.Writer) error
	DecryptBytes(property Property, reader io.Reader) ([]byte, error)
}

// RegisterProvider register provider
func RegisterProvider(provider Provider) {
	injector.Register(prefix+provider.Name(), provider)
}

// RegisterEncryptor register key encrypto
func RegisterEncryptor(name string, f Encryptor) {
	injector.Register(prefix+name, f)
}

// New create key
func New(driver string) (Key, error) {
	var provider Provider
	if !injector.Get(prefix+driver, &provider) {
		return nil, xerrors.Wrapf(ErrDriver, "unknown driver %s", driver)
	}

	return provider.New()
}

// From create key from exist key
func From(driver string, key Key) (Key, error) {
	toKey, err := New(driver)

	if err != nil {
		return nil, err
	}

	toKey.SetBytes(key.PriKey())

	return toKey, nil
}

// ValidAddress .
func ValidAddress(driver string, address string) (bool, error) {
	var provider Provider
	if !injector.Get(prefix+driver, &provider) {
		return false, xerrors.Wrapf(ErrDriver, "unknown driver %s", driver)
	}

	return provider.ValidAddress(address), nil
}

// Recover recover public key from sig and hash
func Recover(driver string, sig []byte, hash []byte) ([]byte, error) {
	var provider RecoverableProvider
	if !injector.Get(prefix+driver, &provider) {
		return nil, xerrors.Wrapf(ErrDriver, "unknown driver %s", driver)
	}

	return provider.Recover(sig, hash)
}

// PublicKeyToAddress .
func PublicKeyToAddress(driver string, pubkey []byte) (string, error) {
	var provider Provider
	if !injector.Get(prefix+driver, &provider) {
		return "", xerrors.Wrapf(ErrDriver, "unknown driver %s", driver)
	}

	return provider.PublicKeyToAddress(pubkey)
}

// Verify .
func Verify(driver string, pubkey []byte, sig []byte, hash []byte) (bool, error) {
	var provider Provider
	if !injector.Get(prefix+driver, &provider) {
		return false, xerrors.Wrapf(ErrDriver, "unknown driver %s", driver)
	}

	return provider.Verify(pubkey, sig, hash), nil
}

func getEncryptor(name string) (Encryptor, error) {
	var ef Encryptor
	if !injector.Get(prefix+name, &ef) {
		return nil, xerrors.Wrapf(ErrDriver, "unknown encryptor %s", name)
	}

	return ef, nil
}

// Encrypt .
func Encrypt(encryptor string, key Key, attrs Property, writer io.Writer) error {
	ec, err := getEncryptor(encryptor)

	if err != nil {
		return err
	}

	return ec.Encrypt(key, attrs, writer)
}

// Decrypt .
func Decrypt(encryptor string, key Key, attrs Property, reader io.Reader) error {
	ec, err := getEncryptor(encryptor)

	if err != nil {
		return err
	}

	err = ec.Decrypt(key, attrs, reader)

	if err != nil {
		return xerrors.Wrapf(err, "decrypt with encryptor %s failed", encryptor)
	}

	return nil
}

// MnemonicToKeystore .
func MnemonicToKeystore(mnemonic string, password string, writer io.Writer) error {

	ec, err := getEncryptor("web3.light")

	if err != nil {
		return err
	}

	bytesec, _ := ec.(BytesEncryptor)

	return bytesec.EncryptBytes([]byte(mnemonic), Property{"password": password}, writer)
}

// MnemonicFromKeystore .
func MnemonicFromKeystore(reader io.Reader, password string) (string, error) {

	ec, err := getEncryptor("web3.light")

	if err != nil {
		return "", err
	}

	bytesec, _ := ec.(BytesEncryptor)

	buff, err := bytesec.DecryptBytes(Property{"password": password}, reader)

	if err != nil {
		return "", err
	}

	return string(buff), nil
}

// NewMnemonic .
func NewMnemonic(driver string, path string) (string, Key, error) {

	var provider Provider
	if !injector.Get(prefix+driver, &provider) {
		return "", nil, xerrors.Wrapf(ErrDriver, "unknown driver %s", driver)
	}

	seed := make([]byte, 16)

	_, err := rand.Read(seed)

	if err != nil {
		return "", nil, xerrors.Wrapf(err, "create seed error")
	}

	mnemonic, err := bip39.NewMnemonic(seed, bip39.ENUS())

	if err != nil {
		return "", nil, xerrors.Wrapf(err, "create mnemonic error")
	}

	key, err := fromMnemonic(provider, mnemonic, path)

	return mnemonic, key, err
}

// NewMnemonicWithLength .
func NewMnemonicWithLength(driver string, path string, length int) (string, Key, error) {

	var provider Provider
	if !injector.Get(prefix+driver, &provider) {
		return "", nil, xerrors.Wrapf(ErrDriver, "unknown driver %s", driver)
	}

	seed := make([]byte, length)

	_, err := rand.Read(seed)

	if err != nil {
		return "", nil, xerrors.Wrapf(err, "create seed error")
	}

	mnemonic, err := bip39.NewMnemonic(seed, bip39.ENUS())

	if err != nil {
		return "", nil, xerrors.Wrapf(err, "create mnemonic error")
	}

	key, err := fromMnemonic(provider, mnemonic, path)

	return mnemonic, key, err
}

func fromMnemonic(provider Provider, mnemonic string, path string) (Key, error) {
	masterkey, err := bip32.FromMnemonic(provider, mnemonic, "")

	if err != nil {
		return nil, xerrors.Wrapf(err, "create master key from mnemonic error")
	}

	privateKeyBytes, err := bip32.DriveFrom(masterkey, path)

	if err != nil {
		return nil, err
	}

	key, err := provider.New()

	if err != nil {
		return nil, err
	}

	key.SetBytes(privateKeyBytes)

	return key, nil
}

// FromMnemonic .
func FromMnemonic(driver string, mnemonic string, path string) (Key, error) {

	var provider Provider
	if !injector.Get(prefix+driver, &provider) {
		return nil, xerrors.Wrapf(ErrDriver, "unknown driver %s", driver)
	}
	// println(path)
	// if driver == "bnb" {
	// 	return bnb.NewMnemonicKeyManager(mnemonic)
	// }

	return fromMnemonic(provider, mnemonic, path)
}

// EncryptBlock .
func EncryptBlock(driver string, pubkey []byte, message []byte) ([]byte, error) {
	var provider Provider
	if !injector.Get(prefix+driver, &provider) {
		return nil, xerrors.Wrapf(ErrDriver, "unknown driver %s", driver)
	}

	return ecies.Encrypt(rand.Reader, ecies.ImportECDSAPublic(ecdsax.BytesToPublicKey(provider.Curve(), pubkey)), message, nil, nil)
}

// DecryptBlock .
func DecryptBlock(key Key, message []byte) ([]byte, error) {
	return ecies.ImportECDSA(ecdsax.BytesToPrivateKey(key.PriKey(), key.Provider().Curve())).Decrypt(message, nil, nil)
}
