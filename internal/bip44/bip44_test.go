package bip44

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHardened(t *testing.T) {

	n := MakeNumber(1, true)

	require.True(t, n.IsHardened())

	require.Equal(t, n.Value(), 1)

	n = MakeNumber(1, false)

	require.False(t, n.IsHardened())

}

func TestRegex(t *testing.T) {
	pathRegex.Longest()

	submatch := pathRegex.FindStringSubmatch("m/44'/60'/0'/1/0")

	println(printResult(submatch))

	require.False(t, pathRegex.MatchString("m/44'/60'/0'/"))
}

func TestParse(t *testing.T) {
	_, err := Parse("m/44'/60'/0'/0/0")

	require.NoError(t, err)
}

func printResult(val interface{}) string {
	buff, _ := json.MarshalIndent(val, "", "\t")

	return string(buff)
}
