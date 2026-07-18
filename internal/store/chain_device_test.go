package store

import "testing"

func TestChainDeviceValidation(t *testing.T) {
	// ingress/egress require a device.
	c := Chain{Name: "ig", Kind: "base", Hook: "ingress", ChainType: "filter", Priority: "0"}
	if errs := c.Validate(); len(errs) == 0 {
		t.Fatal("ingress without a device should be rejected")
	}
	c.Device = "eth0"
	if errs := c.Validate(); len(errs) != 0 {
		t.Fatalf("ingress with a device should validate: %v", errs)
	}
	// A non-device hook must not keep a device.
	c2 := Chain{Name: "in", Kind: "base", Hook: "input", ChainType: "filter", Priority: "filter", Device: "eth0"}
	if errs := c2.Validate(); len(errs) != 0 {
		t.Fatalf("input chain should validate: %v", errs)
	}
	if c2.Device != "" {
		t.Fatalf("device should be cleared for a non-ingress hook, got %q", c2.Device)
	}
	// A bad interface name is rejected.
	c3 := Chain{Name: "ig", Kind: "base", Hook: "ingress", ChainType: "filter", Priority: "0", Device: "bad name!"}
	if errs := c3.Validate(); len(errs) == 0 {
		t.Fatal("a malformed device name should be rejected")
	}
}
