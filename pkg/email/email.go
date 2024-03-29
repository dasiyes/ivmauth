package email

import (
	"bytes"
	"fmt"
	"net/smtp"
	"text/template"

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
	from := cfg.SendFrom
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
		header["To"] = toList
	}
	header["MIME-Version"] = "1.0"
	header["Content-Type"] = "text/html; charset=\"utf-8\""
	// header["Content-Transfer-Encoding"] = "base64"
	header["Subject"] = fmt.Sprintf("%s\r\n", e.Subject)

	var msg string
	for k, v := range header {
		msg += fmt.Sprintf("%s: %s\r\n", k, v)
	}

	// Message.
	var message = []byte(fmt.Sprintf("%s\n\n%s", msg, e.Message))

	// Authentication.
	auth := smtp.PlainAuth("", from, password, smtpHost)

	// Sending email.
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, e.From, to, message)
	if err != nil {
		fmt.Printf("[SendMessageFromEmail] error:%v\n", err)
		return err
	}
	fmt.Println("Email Sent Successfully!")
	return nil
}

// ParseTemplate will be used to send emails in HTML format
func (e *Email) ParseTemplate(templateFileName string, data interface{}) error {
	t, err := template.ParseFiles(templateFileName)
	if err != nil {
		return err
	}
	buf := new(bytes.Buffer)
	if err = t.Execute(buf, data); err != nil {
		return err
	}
	e.Message = fmt.Sprintf("\n\n%s\n\n", buf.String())
	return nil
}
