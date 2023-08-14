package dhcp

import (
	"testing"
	"time"
)

func TestDHCP(t *testing.T) {
	server := New()
	defer server.Stop()
	server.Start()
	time.Sleep(time.Second * 30)
}
