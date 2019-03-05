package password

import (
	"errors"
	"fmt"
	"regexp"

	"policies"
)

// PolicyCheck receives a password and checks it
// against all password policies
// IF no policies are passed to PolicyCheck, the
// default policies will be used
func PolicyCheck(v interface{}, policyFuncs ...policies.PolicyFunc) error {
	if len := len(policyFuncs); len == 0 {
		policyFuncs = defaultPolicies()
	}
	return policies.PolicyCheck(v, policyFuncs...)
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
	if len := len(policies.String(v)); len < 3 {
		return errors.New("password must contain no less than 3 characters")
	}
	return nil
}

func maximumLengthPolicy(v interface{}) error {
	if len := len(policies.String(v)); 40 < len {
		return errors.New("password must contain no more than 40 characters")
	}
	return nil
}

func uppercasePolicy(v interface{}) error {
	r := regexp.MustCompile(`[A-Z]+`)
	if !r.MatchString(policies.String(v)) {
		return errors.New("password must contain no less than 1 uppercase letter")
	}
	return nil
}

func lowercasePolicy(v interface{}) error {
	r := regexp.MustCompile(`[a-z]+`)
	if !r.MatchString(policies.String(v)) {
		return errors.New("password must contain at least 1 lowercase letter")
	}
	return nil
}

func specialCharacterPolicy(v interface{}) error {
	const runes = "!@#$%^&*()"
	r := regexp.MustCompile(fmt.Sprintf("[%s]+", runes))
	if !r.MatchString(policies.String(v)) {
		return errors.New(fmt.Sprintf("password must contain no less than 1 special character: (i.e. %s)", runes))
	}
	return nil
}
