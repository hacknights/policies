package password

import (
	"errors"
	"fmt"
	"testing"

	"github.com/hacknights/testing/assert"
)

const minimumLengthError = "password must contain no less than 3 characters"

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

const maximumLengthError = "password must contain no more than 40 characters"

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

const uppercaseError = "password must contain no less than 1 uppercase letter"

func TestUppercasePolicy_0(t *testing.T) {
	if err := uppercasePolicy("ab"); err.Error() != uppercaseError {
		assert.Error(t, uppercaseError, err)
	}
}

func TestUppercasePolicy_1(t *testing.T) {
	if err := uppercasePolicy("aB"); err != nil {
		assert.Error(t, nil, err)
	}
}

const lowercaseError = "password must contain at least 1 lowercase letter"

func TestLowercasePolicy_0(t *testing.T) {
	if err := lowercasePolicy("AB"); err.Error() != lowercaseError {
		assert.Error(t, lowercaseError, err)
	}
}

func TestLowercasePolicy_1(t *testing.T) {
	if err := lowercasePolicy("Ab"); err != nil {
		assert.Error(t, nil, err)
	}
}

const specialCharacterError = "password must contain no less than 1 special character: (i.e. !@#$%^&*())"

func TestSpecialCharacterPolicy_0(t *testing.T) {
	if err := specialCharacterPolicy("Qw3"); err.Error() != specialCharacterError {
		assert.Error(t, specialCharacterError, err)
	}
}

func TestSpecialCharacterPolicy_1(t *testing.T) {
	if err := specialCharacterPolicy("Qw$"); err != nil {
		assert.Error(t, nil, err)
	}
}

var policyCheckerError string = fmt.Sprintf("%s\n%s\n%s\n%s", minimumLengthError, uppercaseError, lowercaseError, specialCharacterError)

func TestPolicyCheck_0_0(t *testing.T) {
	pc := NewPasswordPolicyChecker()
	if err := pc.PolicyCheck(""); err.Error() != policyCheckerError {
		assert.Error(t, policyCheckerError, err)
	}
}

func TestPolicyCheck__0(t *testing.T) {
	pc := NewPasswordPolicyChecker()
	if err := pc.PolicyCheck("mYpa$"); err != nil {
		assert.Error(t, nil, err)
	}
}

func TestPolicyCheck__1(t *testing.T) {
	pc := NewPasswordPolicyChecker()
	if err := pc.PolicyCheck("", func(v interface{}) error {
		if len := len(password(v)); len != 0 {
			return errors.New("FAILED")
		}
		return nil
	}); err != nil {
		assert.Error(t, nil, err)
	}
}
