package password

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/hacknights/messages"
)

type password struct{}

// NewPassword returns a pointer
// to a password polic
func NewPassword() *password {
	return &password{}
}

// Check receives a password and checks it
// against all password policies
func (p *password) Check(password string) error {
	b := messages.NewErrorBuilder()
	if err := p.length(password); err != nil {
		b.WriteError(err)
	}

	if err := p.uppercase(password); err != nil {
		b.WriteError(err)
	}

	if err := p.lowercase(password); err != nil {
		b.WriteError(err)
	}

	if err := p.specialCharacter(password); err != nil {
		b.WriteError(err)
	}

	if err := b.Error(); err != nil {
		return err
	}
	return nil
}

func (p *password) length(password string) error {
	if len := len(password); len < 3 || 40 < len {
		return errors.New("password must be greater than 3 and less than 40")
	}
	return nil
}

func (p *password) uppercase(password string) error {
	r := regexp.MustCompile(`[A-Z]+`)
	if !r.MatchString(password) {
		return errors.New("password must contain at least 1 uppercase letter")
	}
	return nil
}

func (p *password) lowercase(password string) error {
	r := regexp.MustCompile(`[a-z]+`)
	if !r.MatchString(password) {
		return errors.New("password must contain at least 1 lowercase letter")
	}
	return nil
}

func (p *password) specialCharacter(password string) error {
	const runes = "!@#$%^&*()"
	r := regexp.MustCompile(fmt.Sprintf("[%s]+", runes))
	if !r.MatchString(password) {
		return errors.New(fmt.Sprintf("password must contain at least 1 special character: (i.e. %s)", runes))
	}
	return nil
}
