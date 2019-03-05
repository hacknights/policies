package policies

import "messages"

// PolicyFunc if the function used by all
// implementations of PolicyChecker
type PolicyFunc func(v interface{}) error

// PolicyChecker is the interface implemented by an object that can
// check a value against the received policies
type PolicyChecker interface {
	PolicyCheck(v interface{}, policyFuncs ...PolicyFunc) error
}

// PolicyCheck receives a value and checks it
// against all received policyFuncs
func PolicyCheck(v interface{}, policyFuncs ...PolicyFunc) error {
	eb := messages.NewErrorBuilder()
	for _, p := range policyFuncs {
		if err := p(v); err != nil {
			eb.WriteError(err)
		}
	}
	return eb.Error()
}

// String asserts the interface value
// holds a string
func String(v interface{}) string {
	return v.(string)
}
