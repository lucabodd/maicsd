package utils

import (
    	"strings"
        "encoding/base64"
        "net/smtp"
)

func SendMail(addr, from, subject, body string, to []string) error {
	r := strings.NewReplacer("\r\n", "", "\r", "", "\n", "", "%0a", "", "%0d", "")

	c, err := smtp.Dial(addr)
	Check(err)
	defer c.Close()
	err = c.Mail(r.Replace(from))
	Check(err)
	for i := range to {
		to[i] = r.Replace(to[i])
		err = c.Rcpt(to[i])
		Check(err)
	}

	w, err := c.Data()
	Check(err)

	msg := "To: " + strings.Join(to, ",") + "\r\n" +
		"From: " + from + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/html; charset=\"UTF-8\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" + base64.StdEncoding.EncodeToString([]byte(body))

	_, err = w.Write([]byte(msg))
	Check(err)
	err = w.Close()
	Check(err)
	return c.Quit()
}
