package password

import (
	"errors"
	"fmt"
	"messages"
	"regexp"

	"policies"
)

type passwordPolicyChecker struct{}

// NewPasswordPolicyChecker returns a pointer to a
// passwordPolicyChecker
func NewPasswordPolicyChecker() *passwordPolicyChecker {
	return &passwordPolicyChecker{}
}

// PolicyCheck receives a password and checks it
// against all password policies
// IF no policies are passed to PolicyCheck, the
// default policies will be used
func (p *passwordPolicyChecker) PolicyCheck(v interface{}, policies ...policies.PolicyFunc) error {
	if len := len(policies); len == 0 {
		policies = defaultPolicies()
	}

	eb := messages.NewErrorBuilder()
	for _, p := range policies {
		if err := p(v); err != nil {
			eb.WriteError(err)
		}
	}
	return eb.Error()
}

func defaultPolicies() []policies.PolicyFunc {
	policies := []policies.PolicyFunc{}
	policies = append(policies, minimumLengthPolicy)
	policies = append(policies, maximumLengthPolicy)
	policies = append(policies, uppercasePolicy)
	policies = append(policies, lowercasePolicy)
	policies = append(policies, specialCharacterPolicy)
	return policies
}

func minimumLengthPolicy(v interface{}) error {
	if len := len(password(v)); len < 3 {
		return errors.New("password must contain no less than 3 characters")
	}
	return nil
}

func maximumLengthPolicy(v interface{}) error {
	if len := len(password(v)); 40 < len {
		return errors.New("password must contain no more than 40 characters")
	}
	return nil
}

func uppercasePolicy(v interface{}) error {
	r := regexp.MustCompile(`[A-Z]+`)
	if !r.MatchString(password(v)) {
		return errors.New("password must contain no less than 1 uppercase letter")
	}
	return nil
}

func lowercasePolicy(v interface{}) error {
	r := regexp.MustCompile(`[a-z]+`)
	if !r.MatchString(password(v)) {
		return errors.New("password must contain at least 1 lowercase letter")
	}
	return nil
}

func specialCharacterPolicy(v interface{}) error {
	const runes = "!@#$%^&*()"
	r := regexp.MustCompile(fmt.Sprintf("[%s]+", runes))
	if !r.MatchString(password(v)) {
		return errors.New(fmt.Sprintf("password must contain no less than 1 special character: (i.e. %s)", runes))
	}
	return nil
}

func password(v interface{}) string {
	return v.(string)
}
