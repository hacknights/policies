package policies

import (
	"errors"
	"testing"

	"github.com/hacknights/testing/assert"
)

func TestPolicyCheck_0_0(t *testing.T) {
	if err := PolicyCheck(""); err != nil {
		assert.Error(t, nil, err)
	}
}

func TestPolicyCheck_0_1(t *testing.T) {
	if err := PolicyCheck("", func(v interface{}) error {
		if String(v) != "" {
			return errors.New("FAILED")
		}
		return nil
	}); err != nil {
		assert.Error(t, nil, err)
	}
}

func TestString(t *testing.T) {
	const expected = "test"
	if s := String(expected); s != expected {
		assert.Fail(t, expected, s)
	}
}
