package email

import (
	"errors"
	"net/mail"
	"policies"
)

// PolicyCheck receives an email and checks it
// against all email policies
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
	policies = append(policies, parsedEmailPolicy)
	return policies
}

func parsedEmailPolicy(v interface{}) error {
	if _, err := mail.ParseAddress(policies.String(v)); err != nil {
		return errors.New("invalid email address")
	}
	return nil
}
