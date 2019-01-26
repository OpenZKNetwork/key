package bip44

import (
	"errors"
	"regexp"
	"strconv"
	"strings"

	"github.com/dynamicgo/xerrors"
)

// errors .
var (
	ErrPath = errors.New("path error")
)

// Number .
type Number uint64

var pathRegex = regexp.MustCompile("m/(\\d+'?)/(\\d+'?)/(\\d+'?)/([0,1])/(\\d+'?)")

// HardenedBit .
const HardenedBit = Number(0x80000000)

// MakeNumber .
func MakeNumber(val uint64, hardened bool) Number {
	if hardened {
		return 0x80000000 | Number(val)
	}

	return Number(val)
}

// ParseNumber .
func ParseNumber(val string) (Number, error) {

	hardened := false

	if strings.HasSuffix(val, "'") {
		val = strings.TrimSuffix(val, "'")
		hardened = true
	}

	u, err := strconv.ParseUint(val, 10, 64)

	if err != nil {
		return HardenedBit, xerrors.Wrapf(err, "parse uint %s error", val)
	}

	return MakeNumber(u, hardened), nil
}

// IsHardened .
func (number Number) IsHardened() bool {
	return (number & Number(HardenedBit)) != 0
}

// Value .
func (number Number) Value() int {
	return int(number & (Number(^HardenedBit)))
}

// DeterministicPath .
type DeterministicPath struct {
	Purpose Number
	Coin    Number
	Account Number
	Change  Number
	Address Number
}

// Parse parse bip44 path string
func Parse(path string) (*DeterministicPath, error) {

	if !pathRegex.MatchString(path) {
		return nil, xerrors.Wrapf(ErrPath, "invalid path %s", path)
	}

	tokens := pathRegex.FindStringSubmatch(path)

	if len(tokens) == 0 {
		return nil, xerrors.Wrapf(ErrPath, "no match path %s", path)
	}

	if tokens[0] != path {
		return nil, xerrors.Wrapf(ErrPath, "no match path %s", path)
	}

	purpose, err := ParseNumber(tokens[1])

	if err != nil {
		return nil, err
	}

	coin, err := ParseNumber(tokens[2])

	if err != nil {
		return nil, err
	}

	account, err := ParseNumber(tokens[3])

	if err != nil {
		return nil, err
	}

	change, err := ParseNumber(tokens[4])

	if err != nil {
		return nil, err
	}

	address, err := ParseNumber(tokens[5])

	if err != nil {
		return nil, err
	}

	return &DeterministicPath{
		Purpose: purpose,
		Coin:    coin,
		Account: account,
		Change:  change,
		Address: address,
	}, nil
}
