// Package notify delivers nftably alerts to the operator's configured
// destinations — a generic JSON webhook, Slack, Discord, or email. Each gets a
// payload shaped for its platform. No enabled destinations means every call is a
// silent no-op. Adapted from the sister project birdy.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/floreabogdan/nftably/internal/store"
)

// throttled are the storm-prone kinds a cooldown applies to. Operator-initiated
// events (apply/rollback) are infrequent and always go through.
var throttled = map[string]bool{
	store.AlertAutoBan: true, store.AlertFeedFailed: true,
	store.AlertNftDown: true, store.AlertNftUp: true,
	store.AlertNewExposure: true, store.AlertLoginFailed: true,
	store.AlertConfigDrift: true,
}

// Dispatcher fans one event out to every enabled destination. Safe for
// concurrent use.
type Dispatcher struct {
	store    *store.Store
	log      *slog.Logger
	client   *http.Client
	cooldown time.Duration

	mu   sync.Mutex
	last map[string]time.Time // (kind|subject) -> last delivery, for throttling

	queueOnce sync.Once
	queue     chan notification
}

type notification struct{ kind, subject, message string }

// NewDispatcher builds a dispatcher. cooldown suppresses a repeat of the same
// (kind, subject) within the window; 0 disables throttling.
func NewDispatcher(st *store.Store, log *slog.Logger, cooldown time.Duration) *Dispatcher {
	if log == nil {
		log = slog.Default()
	}
	return &Dispatcher{
		store: st, log: log, cooldown: cooldown,
		client: &http.Client{Timeout: 10 * time.Second},
		last:   map[string]time.Time{},
	}
}

// recentlySent reports whether a throttled (kind, subject) was delivered within
// the cooldown. It only reads — the stamp is written by markSent after a send
// actually succeeds, so a failed delivery never suppresses a later retry.
func (d *Dispatcher) recentlySent(kind, subject string) bool {
	if d.cooldown <= 0 || !throttled[kind] {
		return false
	}
	key := kind + "|" + subject
	d.mu.Lock()
	defer d.mu.Unlock()
	last, ok := d.last[key]
	return ok && time.Since(last) < d.cooldown
}

// markSent records that a throttled (kind, subject) was just delivered, opening
// the cooldown window for it.
func (d *Dispatcher) markSent(kind, subject string) {
	if d.cooldown <= 0 || !throttled[kind] {
		return
	}
	key := kind + "|" + subject
	d.mu.Lock()
	d.last[key] = time.Now()
	d.mu.Unlock()
}

// alert is one thing worth telling the operator, in platform-neutral form.
type alert struct {
	Kind    string
	Subject string // the banned IP, feed name, etc. — extra context
	Message string
	Host    string
	Time    time.Time
}

func (a alert) title() string {
	switch a.Kind {
	case store.AlertApplyReverted:
		return "Firewall config auto-reverted"
	case store.AlertApplyConfirmed:
		return "Firewall config applied"
	case store.AlertApplyRolledBack:
		return "Firewall config rolled back"
	case store.AlertAutoBan:
		return "Source auto-banned: " + a.Subject
	case store.AlertNewExposure:
		return "New exposed service: " + a.Subject
	case store.AlertLoginFailed:
		return "Failed-login burst from " + a.Subject
	case store.AlertFeedFailed:
		return "Blocklist feed failed: " + a.Subject
	case store.AlertNftDown:
		return "nft is unreachable"
	case store.AlertNftUp:
		return "nft is reachable again"
	case store.AlertConfigDrift:
		return "Firewall changed outside nftably"
	default:
		return "nftably alert"
	}
}

func (a alert) severity() string {
	switch a.Kind {
	case store.AlertApplyReverted, store.AlertNftDown, store.AlertFeedFailed, store.AlertNewExposure, store.AlertConfigDrift:
		return "danger"
	case store.AlertApplyConfirmed, store.AlertNftUp:
		return "good"
	case store.AlertApplyRolledBack, store.AlertAutoBan, store.AlertLoginFailed:
		return "warning"
	default:
		return "info"
	}
}

func (a alert) emoji() string {
	switch a.severity() {
	case "danger":
		return "\U0001F534"
	case "good":
		return "\U0001F7E2"
	case "warning":
		return "\U0001F7E1"
	default:
		return "\U0001F4E2"
	}
}

func (a alert) hexColor() string {
	switch a.severity() {
	case "danger":
		return "#d64545"
	case "good":
		return "#2e9e6b"
	case "warning":
		return "#d9a441"
	default:
		return "#3b7dd8"
	}
}

func (a alert) intColor() int {
	switch a.severity() {
	case "danger":
		return 0xd64545
	case "good":
		return 0x2e9e6b
	case "warning":
		return 0xd9a441
	default:
		return 0x3b7dd8
	}
}

func (a alert) plainLine() string {
	line := a.emoji() + " " + a.title()
	if a.Host != "" {
		line += " (" + a.Host + ")"
	}
	if a.Message != "" {
		line += " — " + a.Message
	}
	return line
}

// Notify queues an event for delivery to every enabled destination. A single
// background worker drains the queue, so deliveries keep their order and never
// fan out into an unbounded burst. The queue is bounded; overflow is logged and
// dropped rather than blocking the caller. A delivery failure is logged, not
// retried.
func (d *Dispatcher) Notify(kind, subject, message string) {
	d.queueOnce.Do(func() {
		d.queue = make(chan notification, 256)
		go d.deliverLoop()
	})
	select {
	case d.queue <- notification{kind: kind, subject: subject, message: message}:
	default:
		d.log.Warn("alert queue full; dropping notification", "kind", kind)
	}
}

func (d *Dispatcher) deliverLoop() {
	for n := range d.queue {
		d.deliverAllSync(n.kind, n.subject, n.message)
	}
}

func (d *Dispatcher) deliverAllSync(kind, subject, message string) {
	if d.recentlySent(kind, subject) {
		return
	}
	dests, err := d.store.EnabledAlertDestinations()
	if err != nil {
		d.log.Warn("could not load alert destinations", "error", err)
		return
	}
	if len(dests) == 0 {
		return
	}
	// A recovery follows its outage's subscription: subscribing to "nft down"
	// also gets you "nft up".
	filterKind := kind
	if kind == store.AlertNftUp {
		filterKind = store.AlertNftDown
	}
	a := d.build(kind, subject, message)
	delivered := false
	for _, dest := range dests {
		if !dest.Wants(filterKind) {
			continue
		}
		if err := d.deliver(dest, a); err != nil {
			d.log.Warn("alert delivery failed", "destination", dest.Name, "type", dest.Type, "error", err)
			continue
		}
		delivered = true
	}
	// Start the cooldown only once the alert actually went out to someone, so a
	// transient outage doesn't swallow the alerts that follow it.
	if delivered {
		d.markSent(kind, subject)
	}
}

// SendTest delivers a synthetic alert to one destination, inline, so the UI can
// report whether it worked.
func (d *Dispatcher) SendTest(dest store.Destination) error {
	a := d.build("test", "", "This is a test alert from nftably. If you can read this, alerts are wired up.")
	return d.deliver(dest, a)
}

func (d *Dispatcher) build(kind, subject, message string) alert {
	host := ""
	if st, ok, _ := d.store.GetSettings(); ok {
		host = st.RouterLabel
	}
	return alert{Kind: kind, Subject: subject, Message: message, Host: host, Time: time.Now()}
}

func (d *Dispatcher) deliver(dest store.Destination, a alert) error {
	switch dest.Type {
	case store.AlertSlack:
		return d.postJSON(dest.URL, slackPayload(a))
	case store.AlertDiscord:
		return d.postJSON(dest.URL, discordPayload(a))
	case store.AlertEmail:
		return sendEmail(dest, a)
	default:
		return d.postJSON(dest.URL, webhookPayload(a))
	}
}

func (d *Dispatcher) postJSON(url string, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s returned HTTP %d", url, resp.StatusCode)
	}
	return nil
}

// ---- platform payloads ----

func webhookPayload(a alert) map[string]any {
	return map[string]any{
		"text":     a.plainLine(),
		"content":  a.plainLine(),
		"event":    a.Kind,
		"subject":  a.Subject,
		"message":  a.Message,
		"host":     a.Host,
		"severity": a.severity(),
		"time":     a.Time.UTC().Format(time.RFC3339),
	}
}

func slackPayload(a alert) map[string]any {
	fields := []map[string]any{{"title": "Event", "value": a.Kind, "short": true}}
	if a.Host != "" {
		fields = append(fields, map[string]any{"title": "Host", "value": a.Host, "short": true})
	}
	return map[string]any{
		"attachments": []map[string]any{{
			"fallback": a.plainLine(),
			"color":    a.hexColor(),
			"title":    a.emoji() + " " + a.title(),
			"text":     a.Message,
			"fields":   fields,
			"footer":   "nftably",
			"ts":       a.Time.Unix(),
		}},
	}
}

func discordPayload(a alert) map[string]any {
	fields := []map[string]any{{"name": "Event", "value": a.Kind, "inline": true}}
	if a.Host != "" {
		fields = append(fields, map[string]any{"name": "Host", "value": a.Host, "inline": true})
	}
	return map[string]any{
		"embeds": []map[string]any{{
			"title":       a.emoji() + " " + a.title(),
			"description": a.Message,
			"color":       a.intColor(),
			"fields":      fields,
			"footer":      map[string]any{"text": "nftably"},
			"timestamp":   a.Time.UTC().Format(time.RFC3339),
		}},
	}
}
