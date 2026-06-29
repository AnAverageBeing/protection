package alerts

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"

	"protection/internal/config"
	"protection/internal/core"
)

// SMTP sends plain-text email alerts. It supports both implicit TLS (port 465)
// and STARTTLS (port 587), as well as unauthenticated relays.
type SMTP struct {
	cfg      config.SMTPConfig
	hostname string
	min      core.Severity
}

// NewSMTP builds an email alerter.
func NewSMTP(cfg config.SMTPConfig, hostname string) *SMTP {
	return &SMTP{cfg: cfg, hostname: hostname, min: core.ParseSeverity(cfg.MinSeverity)}
}

func (s *SMTP) Name() string               { return "smtp" }
func (s *SMTP) MinSeverity() core.Severity { return s.min }

func (s *SMTP) Send(ctx context.Context, ev core.Event) error {
	msg := s.buildMessage(ev)
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)

	var auth smtp.Auth
	if s.cfg.Username != "" {
		auth = smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
	}

	// Implicit TLS (typically 465): dial a TLS connection up front.
	if s.cfg.TLS && s.cfg.Port == 465 {
		return s.sendImplicitTLS(addr, auth, msg)
	}
	// Plain / STARTTLS path handled by net/smtp.SendMail (it issues STARTTLS
	// automatically when the server advertises it).
	return smtp.SendMail(addr, auth, s.cfg.From, s.cfg.To, msg)
}

func (s *SMTP) sendImplicitTLS(addr string, auth smtp.Auth, msg []byte) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: s.cfg.Host})
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		return err
	}
	defer c.Quit()
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail(s.cfg.From); err != nil {
		return err
	}
	for _, rcpt := range s.cfg.To {
		if err := c.Rcpt(rcpt); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	return w.Close()
}

func (s *SMTP) buildMessage(ev core.Event) []byte {
	var b strings.Builder
	subject := fmt.Sprintf("[protection][%s] %s on %s", strings.ToUpper(ev.Severity.String()), ev.Title, s.hostname)
	fmt.Fprintf(&b, "From: %s\r\n", s.cfg.From)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(s.cfg.To, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")

	fmt.Fprintf(&b, "%s\n\n", ev.Description)
	for _, kv := range fieldsFor(ev, s.hostname) {
		fmt.Fprintf(&b, "%-12s: %s\n", kv[0], kv[1])
	}
	if len(ev.Evidence) > 0 {
		b.WriteString("\nEvidence:\n")
		for k, v := range ev.Evidence {
			fmt.Fprintf(&b, "  %s = %s\n", k, v)
		}
	}
	fmt.Fprintf(&b, "\nTime: %s\n", ev.Time.UTC().Format("2006-01-02 15:04:05 UTC"))
	return []byte(b.String())
}
