package cli

import "testing"

func TestMaskedInputTypingIsAllStars(t *testing.T) {
	m := &maskedInput{}
	for _, c := range "hunter2" {
		m.feed([]byte(string(c)))
	}
	if got := m.mask(); got != "*******  (7 chars)" {
		t.Fatalf("mask = %q", got)
	}
}

func TestMaskedInputBracketedPasteShowsTail(t *testing.T) {
	m := &maskedInput{}
	m.feed([]byte("\x1b[200~sk-abcdefXYZ\x1b[201~"))
	if got := m.mask(); got != "*********XYZ  (12 chars)" {
		t.Fatalf("mask = %q", got)
	}
	m.feed([]byte("\r"))
	if !m.done || string(m.buf) != "sk-abcdefXYZ" {
		t.Fatalf("done=%v buf=%q", m.done, m.buf)
	}
}

func TestMaskedInputBurstPasteShowsTailAndTypingHidesIt(t *testing.T) {
	m := &maskedInput{}
	m.feed([]byte("abcdef"))
	if got := m.mask(); got != "***def  (6 chars)" {
		t.Fatalf("mask = %q", got)
	}
	m.feed([]byte("g"))
	if got := m.mask(); got != "*******  (7 chars)" {
		t.Fatalf("mask after typing = %q", got)
	}
}

func TestMaskedInputBackspaceAndCtrlC(t *testing.T) {
	m := &maskedInput{}
	m.feed([]byte("ab"))
	m.feed([]byte{127})
	if string(m.buf) != "a" {
		t.Fatalf("buf = %q", m.buf)
	}
	if err := m.feed([]byte{3}); err != errAborted {
		t.Fatalf("err = %v", err)
	}
}

func TestMaskedInputLongValueCapsStars(t *testing.T) {
	m := &maskedInput{}
	m.feed([]byte("\x1b[200~" + string(make([]byte, 0)) + "0123456789012345678901234567890123456789\x1b[201~"))
	if got := m.mask(); got != "********************************…789  (40 chars)" {
		t.Fatalf("mask = %q", got)
	}
}
