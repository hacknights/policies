package policies

type PolicyFunc func(v interface{}) error

type PolicyChecker interface {
	PolicyCheck(v interface{}, policies ...PolicyFunc) error
}
