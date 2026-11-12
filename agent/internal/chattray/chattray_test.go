// SPDX-License-Identifier: AGPL-3.0-only
package chattray

import (
	"encoding/binary"
	"os"
	"testing"
)

func TestErrUnsupportedHasMessage(t *testing.T) {
	if ErrUnsupported == nil || ErrUnsupported.Error() == "" {
		t.Fatal("ErrUnsupported must carry a message")
	}
}

func TestActionForMessage(t *testing.T) {
	tests := []struct {
		name string
		msg  uint32
		want action
	}{
		{"left click opens", wmLButtonUp, actOpen},
		{"double click opens", wmLButtonDbl, actOpen},
		{"right click shows menu", wmRButtonUp, actMenu},
		{"keyboard context menu", wmContextMenu, actMenu},
		{"mouse move ignored", 0x0200, actNone},
		{"left button down ignored", 0x0201, actNone},
	}
	for _, tt := range tests {
		if got := actionForMessage(tt.msg); got != tt.want {
			t.Errorf("%s: actionForMessage(0x%x) = %d, want %d", tt.name, tt.msg, got, tt.want)
		}
	}
}

func TestActionForMenu(t *testing.T) {
	tests := []struct {
		cmd  uintptr
		want action
	}{
		{0, actNone}, // dismissed
		{idOpen, actOpen},
		{idExit, actExit},
		{99, actNone},
	}
	for _, tt := range tests {
		if got := actionForMenu(tt.cmd); got != tt.want {
			t.Errorf("actionForMenu(%d) = %d, want %d", tt.cmd, got, tt.want)
		}
	}
}

func TestFailureBody(t *testing.T) {
	if got := failureBody(""); got != "NodeLink Support could not open." {
		t.Errorf("empty error body = %q", got)
	}
	if got := failureBody("service stopped"); got != "service stopped" {
		t.Errorf("error body = %q", got)
	}
}

func TestPickIcoEntrySelectsAValidImage(t *testing.T) {
	data, err := os.ReadFile("nodelink.ico")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []int{16, 32, 256} {
		off, size, err := pickIcoEntry(data, want)
		if err != nil {
			t.Fatalf("embedded icon did not parse for %dpx: %v", want, err)
		}
		if off == 0 || size == 0 || uint64(off)+uint64(size) > uint64(len(data)) {
			t.Fatalf("%dpx: bad image range %d+%d of %d", want, off, size, len(data))
		}
	}
}

// ico builds a container whose directory entries have the given widths and
// image ranges; payload bytes are zero.
func ico(entries ...[3]uint32) []byte {
	data := make([]byte, 6+16*len(entries), 512)
	binary.LittleEndian.PutUint16(data[2:], 1)
	binary.LittleEndian.PutUint16(data[4:], uint16(len(entries)))
	for i, e := range entries {
		dir := data[6+16*i:]
		dir[0] = byte(e[0])
		binary.LittleEndian.PutUint32(dir[8:], e[2])
		binary.LittleEndian.PutUint32(dir[12:], e[1])
	}
	return data[:cap(data)]
}

func TestPickIcoEntryChoosesClosestValidWidth(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    int
		wantOff uint32
		wantErr bool
	}{
		{"exact match wins", ico([3]uint32{32, 100, 10}, [3]uint32{16, 200, 10}), 16, 200, false},
		{"nearest when no exact", ico([3]uint32{48, 100, 10}, [3]uint32{24, 200, 10}), 20, 200, false},
		{"width 0 means 256", ico([3]uint32{0, 100, 10}, [3]uint32{16, 200, 10}), 256, 100, false},
		{"skips entry past end", ico([3]uint32{16, 500, 100}, [3]uint32{32, 200, 10}), 16, 200, false},
		{"skips zero offset", ico([3]uint32{16, 0, 10}, [3]uint32{32, 200, 10}), 16, 200, false},
		{"skips zero size", ico([3]uint32{16, 100, 0}, [3]uint32{32, 200, 10}), 16, 200, false},
		{"no usable entry", ico([3]uint32{16, 0, 0}), 16, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			off, _, err := pickIcoEntry(tt.data, tt.want)
			if (err != nil) != tt.wantErr || off != tt.wantOff {
				t.Fatalf("pickIcoEntry = %d, %v; want %d, err=%v", off, err, tt.wantOff, tt.wantErr)
			}
		})
	}
}

func TestPickIcoEntryRejectsMalformed(t *testing.T) {
	for _, bad := range [][]byte{
		nil,
		{0, 0, 0},
		{1, 0, 1, 0, 1, 0},       // nonzero reserved field
		{0, 0, 2, 0, 1, 0},       // wrong type (2, not 1)
		{0, 0, 1, 0, 0, 0},       // zero images
		{0, 0, 1, 0, 2, 0, 0, 0}, // directory truncated
	} {
		if _, _, err := pickIcoEntry(bad, 16); err == nil {
			t.Fatalf("accepted malformed icon: %v", bad)
		}
	}
}
