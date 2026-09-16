//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package chattray

import "testing"

func TestPickIcoEntrySelectsAValidImage(t *testing.T) {
	off, size, err := pickIcoEntry(iconData, 16)
	if err != nil {
		t.Fatalf("embedded icon did not parse: %v", err)
	}
	if off == 0 || size == 0 {
		t.Fatal("selected an empty image range")
	}
	if uint64(off)+uint64(size) > uint64(len(iconData)) {
		t.Fatal("selected range runs past the icon data")
	}
}

func TestPickIcoEntryRejectsMalformed(t *testing.T) {
	for _, bad := range [][]byte{
		nil,
		{0, 0, 0},
		{0, 0, 2, 0, 1, 0}, // wrong type (2, not 1)
		{0, 0, 1, 0, 0, 0}, // zero images
	} {
		if _, _, err := pickIcoEntry(bad, 16); err == nil {
			t.Fatalf("accepted malformed icon: %v", bad)
		}
	}
}

func TestActionForMessage(t *testing.T) {
	cases := map[uint32]action{
		wmLButtonUp:   actOpen,
		wmLButtonDbl:  actOpen,
		wmRButtonUp:   actMenu,
		wmContextMenu: actMenu,
		0x0200:        actNone, // WM_MOUSEMOVE
	}
	for msg, want := range cases {
		if got := actionForMessage(msg); got != want {
			t.Fatalf("actionForMessage(0x%x) = %d, want %d", msg, got, want)
		}
	}
}
