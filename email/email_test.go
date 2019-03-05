package email

import (
	"errors"
	"policies"
	"testing"

	"github.com/hacknights/testing/assert"
)

const parsedEmailError = "invalid email address"

func TestParsedEmailPolicy_0(t *testing.T) {
	if err := parsedEmailPolicy(""); err.Error() != parsedEmailError {
		assert.Error(t, parsedEmailError, err)
	}
}

func TestParsedEmailPolicy_Format_Bad(t *testing.T) {
	if err := parsedEmailPolicy("test@"); err.Error() != parsedEmailError {
		assert.Error(t, parsedEmailError, err)
	}
}

func TestPolicyCheck_0_0(t *testing.T) {
	if err := PolicyCheck(""); err.Error() != parsedEmailError {
		assert.Error(t, parsedEmailError, err)
	}
}

func TestPolicyCheck__0(t *testing.T) {
	if err := PolicyCheck("test@test.com"); err != nil {
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
