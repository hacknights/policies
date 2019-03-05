package username

import (
	"errors"
	"fmt"
	"policies"
)

// PolicyCheck receives a username and checks it
// against all username policies
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
	return policies
}

func minimumLengthPolicy(v interface{}) error {
	const minLength = 3
	if len := len(policies.String(v)); len < minLength {
		return errors.New(fmt.Sprintf("username must contain no less than %d characters", minLength))
	}
	return nil
}

func maximumLengthPolicy(v interface{}) error {
	const maxLength = 40
	if len := len(policies.String(v)); maxLength < len {
		return errors.New(fmt.Sprintf("username must contain no more than %d characters", maxLength))
	}
	return nil
}
