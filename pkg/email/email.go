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

	// toList would list all Receivers in comma separated list
	var toList string
	if len(e.To) == len(e.ToName) {
		for i, v := range e.To {
			toList = toList + fmt.Sprintf("%s <%s>,", e.ToName[i], v)
		}
	}

	header := make(map[string]string)
	header["From"] = fmt.Sprintf("%s <%s>", e.FromName, e.From)
	if toList == "" {
		header["To"] = fmt.Sprintf("%s <%s>", e.ToName, e.To)
	} else {
		header["To"] = fmt.Sprintf("%s", toList)
	}
	header["Subject"] = fmt.Sprintf("%s\n", e.Subject)
	header["MIME-Version"] = "1.0"
	header["Content-Type"] = "text/html; charset=\"utf-8\""
	// header["Content-Transfer-Encoding"] = "base64"

	var msg string
	for k, v := range header {
		msg += fmt.Sprintf("%s: %s\r\n", k, v)
	}

	// Message.
	var message []byte = []byte(fmt.Sprintf("%s\r\n%s", msg, e.Message))
	// if toList == "" {
	// 	message = []byte(fmt.Sprintf("From:%s <%s>\nTo:%s <%s>\nSubject:%s\n\n%s", e.FromName, e.From, e.ToName, e.To, e.Subject, e.Message))
	// } else {
	// 	message = []byte(fmt.Sprintf("From:%s <%s>\nTo:%s\nSubject:%s\n\n%s", e.FromName, e.From, toList, e.Subject, e.Message))
	// }

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
