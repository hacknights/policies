package username

import (
	"errors"
	"policies"
	"testing"

	"github.com/hacknights/testing/assert"
)

const minimumLengthError = "username must contain no less than 3 characters"

func TestMinimumLengthPolicy_0(t *testing.T) {
	if err := minimumLengthPolicy(""); err.Error() != minimumLengthError {
		assert.Error(t, minimumLengthError, err)
	}
}

func TestMinimumLengthPolicy_3(t *testing.T) {
	if err := minimumLengthPolicy("123"); err != nil {
		assert.Error(t, nil, err)
	}
}

const maximumLengthError = "username must contain no more than 40 characters"

func TestMaximumLengthPolicy_41(t *testing.T) {
	const password = "abcdefghijklmnopqrstuvwxyzabcdefghijklmno"
	if err := maximumLengthPolicy(password); err.Error() != maximumLengthError {
		assert.Error(t, maximumLengthError, err)
	}
}

func TestMaximumLengthPolicy_40(t *testing.T) {
	if err := maximumLengthPolicy("abcdefghijklmnopqrstuvwxyzabcdefghijklmn"); err != nil {
		assert.Error(t, nil, err)
	}
}

func TestPolicyCheck_0_0(t *testing.T) {
	if err := PolicyCheck(""); err.Error() != minimumLengthError {
		assert.Error(t, minimumLengthError, err)
	}
}

func TestPolicyCheck__0(t *testing.T) {
	if err := PolicyCheck("mYpa$"); err != nil {
		assert.Error(t, nil, err)
	}
}

func TestPolicyCheck__1(t *testing.T) {
	if err := PolicyCheck("", func(v interface{}) error {
		if len := len(policies.String(v)); len != 0 {
			return errors.New("FAILED")
		}
		return nil
	}); err != nil {
		assert.Error(t, nil, err)
	}
}
