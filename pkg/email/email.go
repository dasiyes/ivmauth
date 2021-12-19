package email

import (
	"fmt"
	"net/smtp"

	ivmcfg "github.com/dasiyes/ivmconfig/src/pkg/config"
)

type Email struct {
	From     string
	To       []string
	FromName string
	ToName   []string
	Subject  string
	Message  string
}

// SendMessageFromEmail is a function that alows
func (e *Email) SendMessageFromEmail(cfg *ivmcfg.EmailCfg) error {

	// Sender data.
	from := e.From
	password := cfg.Password

	// Receiver email address.
	to := e.To

	// smtp server configuration.
	smtpHost := cfg.SmtpHost
	smtpPort := cfg.SmptPort

	// Message.
	message := []byte(fmt.Sprintf("From:%s <%s>\nTo:%s <%s>\nSubject:%s\n\n%s", e.FromName, e.From, e.ToName, e.To, e.Subject, e.Message))

	// Authentication.
	auth := smtp.PlainAuth("", from, password, smtpHost)

	// Sending email.
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, message)
	if err != nil {
		fmt.Printf("[SendMessageFromEmail] error:%v\n", err)
		return err
	}
	fmt.Println("Email Sent Successfully!")
	return nil
}
