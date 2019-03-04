package password

import (
	"testing"

	"github.com/hacknights/testing/assert"
)

const passwordLengthErr = "password must be greater than 3 and less than 40"

func TestPasswordLength_2(t *testing.T) {
	p := NewPassword()
	if err := p.length("ab"); err.Error() != passwordLengthErr {
		assert.Error(t, passwordLengthErr, err)
	}
}

func TestPasswordLength_41(t *testing.T) {
	p := NewPassword()
	if err := p.length("abcdefghijklmnopqrztuvwxyzabcdefghijklmno"); err.Error() != passwordLengthErr {
		assert.Error(t, passwordLengthErr, err)
	}
}

func TestPasswordLength_6(t *testing.T) {
	p := NewPassword()
	if err := p.length("abcdef"); err != nil {
		assert.Error(t, nil, err)
	}
}

const passwordUppercaseErr = "password must contain at least 1 uppercase letter"

func TestPasswordUpperCase_0(t *testing.T) {
	p := NewPassword()
	if err := p.uppercase("ab"); err.Error() != passwordUppercaseErr {
		assert.Error(t, passwordUppercaseErr, err)
	}
}

func TestPasswordUppercase_1(t *testing.T) {
	p := NewPassword()
	if err := p.uppercase("aB"); err != nil {
		assert.Error(t, nil, err)
	}
}

func TestPasswordLowercase_0(t *testing.T) {
	p := NewPassword()
	if err := p.lowercase("AB"); err.Error() != passwordLowercaseErr {
		assert.Error(t, passwordUppercaseErr, nil)
	}
}

const passwordLowercaseErr = "password must contain at least 1 lowercase letter"

func TestPasswordLowercase_1(t *testing.T) {
	p := NewPassword()
	if err := p.lowercase("Ab"); err != nil {
		assert.Error(t, nil, err)
	}
}

const specialCharacterErr = "password must contain at least 1 special character: (i.e. !@#$%^&*())"

func TestPasswordSpecialCharacter_0(t *testing.T) {
	p := NewPassword()
	if err := p.specialCharacter("a4"); err.Error() != specialCharacterErr {
		assert.Error(t, specialCharacterErr, err)
	}
}

func TestPasswordCheck_Errors(t *testing.T) {
	const expected = "password must be greater than 3 and less than 40\npassword must contain at least 1 uppercase letter\npassword must contain at least 1 lowercase letter\npassword must contain at least 1 special character: (i.e. !@#$%^&*())"
	p := NewPassword()
	if err := p.Check(""); err.Error() != expected {
		assert.Error(t, expected, err)
	}
}

func TestPasswordCheck_Pass(t *testing.T) {
	p := NewPassword()
	if err := p.Check("1aB^gtS"); err != nil {
		assert.Error(t, nil, err)
	}
}
