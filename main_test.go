package main

import "testing"

func TestParseJSONPayload(t *testing.T) {
	t.Parallel()

	v, err := parseJSONPayload(`{"text":"hello","n":1}`)
	if err != nil {
		t.Fatalf("expected valid JSON object, got %v", err)
	}
	if v["text"] != "hello" {
		t.Fatalf("expected text=hello")
	}
}

func TestParseJSONPayloadRejectsNonObject(t *testing.T) {
	t.Parallel()

	if _, err := parseJSONPayload(`"hello"`); err == nil {
		t.Fatalf("expected string payload to be rejected")
	}
	if _, err := parseJSONPayload(`[]`); err == nil {
		t.Fatalf("expected array payload to be rejected")
	}
	if _, err := parseJSONPayload(`null`); err == nil {
		t.Fatalf("expected null payload to be rejected")
	}
	if _, err := parseJSONPayload(``); err == nil {
		t.Fatalf("expected empty payload to be rejected")
	}
}

func TestIsLikelyLoopbackAddr(t *testing.T) {
	t.Parallel()

	if !isLikelyLoopbackAddr("127.0.0.1:8787") {
		t.Fatalf("expected 127.0.0.1 to be loopback")
	}
	if !isLikelyLoopbackAddr("localhost:8787") {
		t.Fatalf("expected localhost to be loopback")
	}
	if !isLikelyLoopbackAddr("[::1]:8787") {
		t.Fatalf("expected ::1 to be loopback")
	}
	if isLikelyLoopbackAddr("0.0.0.0:8787") {
		t.Fatalf("expected 0.0.0.0 to be non-loopback")
	}
}
