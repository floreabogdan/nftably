package notify

import (
	"crypto/tls"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/floreabogdan/nftably/internal/store"
)

const smtpTimeout = 15 * time.Second

// sendEmail delivers one alert as an HTML email over SMTP.
func sendEmail(d store.Destination, a alert) error {
	tos := store.SplitAddresses(d.SMTPTo)
	if len(tos) == 0 {
		return fmt.Errorf("no recipients")
	}
	subject := a.emoji() + " nftably: " + a.title()
	return sendSMTP(d, tos, buildMIME(d.SMTPFrom, tos, subject, a.plainText(), emailHTML(a)))
}

// sendSMTP is the transport. It honours the destination's security
// (none / STARTTLS / implicit TLS) and uses AUTH PLAIN when a username is set.
func sendSMTP(d store.Destination, tos []string, msg string) error {
	addr := net.JoinHostPort(d.SMTPHost, fmt.Sprintf("%d", d.SMTPPort))
	var auth smtp.Auth
	if d.SMTPUsername != "" {
		auth = smtp.PlainAuth("", d.SMTPUsername, d.SMTPPassword, d.SMTPHost)
	}
	client, conn, err := dialSMTP(d, addr)
	if err != nil {
		return err
	}
	defer client.Close()

	// net/smtp sets no deadline once the connection is up, so a server that
	// completes the handshake then stalls mid-conversation would hang this
	// goroutine forever — and deliverLoop drains the whole alert queue on a
	// single goroutine, so one stuck email would freeze every other alert.
	// Give each step its own fresh budget.
	step := func() { _ = conn.SetDeadline(time.Now().Add(smtpTimeout)) }

	if d.SMTPSecurity == store.SMTPStartTLS {
		step()
		// The operator explicitly asked for STARTTLS; if the server doesn't
		// offer it, fail loudly rather than silently sending the mail in the
		// clear (a stripped capability is exactly the MITM this guards against).
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("starttls requested but the server does not offer it")
		}
		if err := client.StartTLS(&tls.Config{ServerName: d.SMTPHost}); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}
	if auth != nil {
		step()
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	step()
	if err := client.Mail(d.SMTPFrom); err != nil {
		return fmt.Errorf("mail from: %w", err)
	}
	for _, to := range tos {
		step()
		if err := client.Rcpt(to); err != nil {
			return fmt.Errorf("rcpt %s: %w", to, err)
		}
	}
	step()
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}
	step()
	if _, err := wc.Write([]byte(msg)); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	step()
	return client.Quit()
}

// dialSMTP opens a connection with a timeout — net/smtp's own Dial has none, and
// a dead mailserver must not hang the sender. It returns the underlying conn so
// the caller can set per-step deadlines for the rest of the conversation.
func dialSMTP(d store.Destination, addr string) (*smtp.Client, net.Conn, error) {
	var conn net.Conn
	var err error
	if d.SMTPSecurity == store.SMTPTLS {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: smtpTimeout}, "tcp", addr, &tls.Config{ServerName: d.SMTPHost})
		if err != nil {
			return nil, nil, fmt.Errorf("tls dial: %w", err)
		}
	} else {
		conn, err = net.DialTimeout("tcp", addr, smtpTimeout)
		if err != nil {
			return nil, nil, fmt.Errorf("dial: %w", err)
		}
	}
	client, err := smtp.NewClient(conn, d.SMTPHost)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	return client, conn, nil
}

// buildMIME assembles a multipart/alternative message.
func buildMIME(from string, tos []string, subject, textBody, htmlBody string) string {
	boundary := "nftably-boundary-0f8a1c"
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + strings.Join(tos, ", ") + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", subject) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/alternative; boundary=\"" + boundary + "\"\r\n\r\n")

	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n")
	b.WriteString(textBody + "\r\n\r\n")

	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: text/html; charset=\"utf-8\"\r\n\r\n")
	b.WriteString(htmlBody)
	b.WriteString("\r\n--" + boundary + "--\r\n")
	return b.String()
}

func (a alert) plainText() string {
	s := a.plainLine() + "\n"
	if a.Host != "" {
		s += "Host: " + a.Host + "\n"
	}
	return s + "Event: " + a.Kind + "\nTime: " + a.Time.UTC().Format(time.RFC1123Z) + "\n"
}

// emailHTML is a small self-contained card, coloured by severity. Inline styles
// only, because mail clients strip <style> and external CSS.
func emailHTML(a alert) string {
	esc := htmlEscape
	rows := "<tr><td style=\"padding:4px 0;color:#6b7280;width:90px\">Event</td>" +
		"<td style=\"padding:4px 0;color:#111827\"><code>" + esc(a.Kind) + "</code></td></tr>"
	if a.Subject != "" {
		rows += "<tr><td style=\"padding:4px 0;color:#6b7280\">Subject</td>" +
			"<td style=\"padding:4px 0;color:#111827\"><code>" + esc(a.Subject) + "</code></td></tr>"
	}
	if a.Host != "" {
		rows += "<tr><td style=\"padding:4px 0;color:#6b7280\">Host</td>" +
			"<td style=\"padding:4px 0;color:#111827\">" + esc(a.Host) + "</td></tr>"
	}
	rows += "<tr><td style=\"padding:4px 0;color:#6b7280\">Time</td>" +
		"<td style=\"padding:4px 0;color:#111827\">" + esc(a.Time.UTC().Format(time.RFC1123Z)) + "</td></tr>"

	return `<!doctype html><html><body style="margin:0;background:#f3f4f6;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f3f4f6;padding:24px 0">
<tr><td align="center">
<table role="presentation" width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.08)">
<tr><td style="height:6px;background:` + a.hexColor() + `"></td></tr>
<tr><td style="padding:24px">
<div style="font-size:12px;letter-spacing:0.08em;text-transform:uppercase;color:` + a.hexColor() + `;font-weight:700">nftably alert</div>
<div style="font-size:20px;font-weight:700;color:#111827;margin:6px 0 4px">` + esc(a.title()) + `</div>
<div style="font-size:14px;color:#374151;margin-bottom:16px">` + esc(a.Message) + `</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="font-size:13px;border-top:1px solid #e5e7eb;padding-top:8px">` + rows + `</table>
</td></tr>
<tr><td style="padding:12px 24px;background:#f9fafb;color:#9ca3af;font-size:12px">Sent by nftably, your nftables manager.</td></tr>
</table></td></tr></table></body></html>`
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}
