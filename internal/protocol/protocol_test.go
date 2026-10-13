package protocol

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRoundTripAndRejectsInvalid(t *testing.T) {
	want := Envelope{Version: Version, Type: "request", RequestID: "collision-resistant-id", DeviceID: "windows-main", Method: "system.info", Arguments: json.RawMessage(`{}`)}
	b, err := Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if got.RequestID != want.RequestID || got.DeviceID != want.DeviceID || got.Method != want.Method {
		t.Fatalf("roundtrip mismatch: %#v", got)
	}
	for _, bad := range []string{`{"version":2,"type":"hello"}`, `{"version":1,"type":"request","device_id":"d"}`, `{"version":1,"type":"hello","unknown":true}`, `{"version":1,"type":"hello"} {}`} {
		if _, err := Decode(strings.NewReader(bad)); err == nil {
			t.Fatalf("accepted invalid frame %s", bad)
		}
	}
}
func TestFrameLimit(t *testing.T) {
	b := []byte(`{"version":1,"type":"hello"}` + strings.Repeat(" ", MaxFrameBytes))
	if _, err := Decode(bytes.NewReader(b)); err == nil {
		t.Fatal("accepted oversized frame")
	}
}
func TestResponseNeedsStructuredError(t *testing.T) {
	e := Envelope{Version: Version, Type: "response", RequestID: "r"}
	if e.Validate() == nil {
		t.Fatal("accepted failed response without error")
	}
}
