package devices

import (
	"sync"
	"testing"
)

func TestRegistryIsolationAndConcurrentUpdates(t *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := string(rune('a' + i))
			r.Register(Device{ID: id, Name: id})
			r.SetOnline(id, true)
			r.UpdateHeartbeat(id, "v", "windows", "amd64", []string{"fs.read"})
			if d, ok := r.Get(id); !ok || !d.Online || d.OS != "windows" {
				t.Errorf("invalid device state: %#v", d)
			}
		}(i)
	}
	wg.Wait()
	if got := len(r.List()); got != 20 {
		t.Fatalf("got %d devices", got)
	}
}
