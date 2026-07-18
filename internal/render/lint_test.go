package render

import (
	"strings"
	"testing"

	"github.com/floreabogdan/nftably/internal/store"
)

func hasWarnAbout(warns []string, substr string) bool {
	for _, w := range warns {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

func TestLintWarnsOnLockout(t *testing.T) {
	// A drop-policy input chain with no accept at all: warn about both SSH and
	// the UI port.
	m := model("drop")
	warns := Lint(m, "0.0.0.0:8080")
	if !hasWarnAbout(warns, "8080") {
		t.Errorf("expected a UI-port lockout warning, got %v", warns)
	}
	if !hasWarnAbout(warns, "SSH") {
		t.Errorf("expected an SSH lockout warning, got %v", warns)
	}
}

func TestLintQuietWhenAccessAllowed(t *testing.T) {
	// Accept established/related covers an in-progress session for both.
	m := model("drop", rule("replies",
		[]store.RuleMatch{{Key: "ct.state", Op: "==", Value: "established, related"}},
		[]store.RuleStatement{{Key: "accept"}},
	))
	if warns := Lint(m, "0.0.0.0:8080"); len(warns) != 0 {
		t.Errorf("established/related accept should quiet lockout warnings, got %v", warns)
	}
}

func TestLintAcceptPortSatisfies(t *testing.T) {
	m := model("drop",
		rule("ssh", []store.RuleMatch{{Key: "tcp.dport", Op: "==", Value: "22"}}, []store.RuleStatement{{Key: "accept"}}),
		rule("ui", []store.RuleMatch{{Key: "tcp.dport", Op: "==", Value: "8080"}}, []store.RuleStatement{{Key: "accept"}}),
	)
	if warns := Lint(m, "0.0.0.0:8080"); len(warns) != 0 {
		t.Errorf("explicit accepts for 22 and 8080 should be quiet, got %v", warns)
	}
}

func TestLintWarnsOnOutputLockout(t *testing.T) {
	// A drop-policy output chain with nothing accepting replies drops the return
	// traffic of the operator's own session — a lockout the input-only check misses.
	m := Model{Tables: []TableTree{{
		Table: store.Table{Family: "inet", Name: "filter"},
		Chains: []ChainTree{{
			Chain: store.Chain{Name: "output", Kind: "base", Hook: "output", ChainType: "filter", Priority: "filter", Policy: "drop"},
		}},
	}}}
	if warns := Lint(m, "0.0.0.0:8080"); !hasWarnAbout(warns, "output chain drops") {
		t.Errorf("expected an output-chain lockout warning, got %v", warns)
	}

	// An established/related accept in the output chain quiets it.
	m.Tables[0].Chains[0].Rules = []store.ChainRule{rule("replies",
		[]store.RuleMatch{{Key: "ct.state", Op: "==", Value: "established, related"}},
		[]store.RuleStatement{{Key: "accept"}},
	)}
	if warns := Lint(m, "0.0.0.0:8080"); hasWarnAbout(warns, "output chain drops") {
		t.Errorf("established/related accept should quiet the output warning, got %v", warns)
	}
}

func TestLintFlagsUnknownKnob(t *testing.T) {
	m := model("accept", rule("bad",
		[]store.RuleMatch{{Key: "not.a.real.knob", Op: "==", Value: "x"}},
		[]store.RuleStatement{{Key: "accept"}},
	))
	if warns := Lint(m, "0.0.0.0:8080"); !hasWarnAbout(warns, "unknown condition") {
		t.Errorf("expected an unknown-condition warning, got %v", warns)
	}
}
