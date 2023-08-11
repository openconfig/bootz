package entitymanager

import (
	"testing"
)

func TestNew(t *testing.T) {
	_,err:= New("testdata/chassis.prototxt"); if err!=nil {
		t.Fatalf("Could not instantiate entity manager from testdata/chassic.prototxt, err: %v", err)
	}
}