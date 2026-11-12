// SPDX-License-Identifier: AGPL-3.0-only
package chattray

import "encoding/binary"

// The tray's decisions live here, free of Win32, so every OS's test job covers
// them; chattray_windows.go only turns them into calls.

const (
	wmLButtonUp   = 0x0202
	wmLButtonDbl  = 0x0203
	wmRButtonUp   = 0x0205
	wmContextMenu = 0x007B

	idOpen = 1
	idExit = 2
)

type action int

const (
	actNone action = iota
	actOpen
	actMenu
	actExit
)

// actionForMessage maps a tray notification's mouse event to what the tray does.
func actionForMessage(m uint32) action {
	switch m {
	case wmLButtonUp, wmLButtonDbl:
		return actOpen
	case wmRButtonUp, wmContextMenu:
		return actMenu
	}
	return actNone
}

// actionForMenu maps the popup menu's returned command; 0 means dismissed.
func actionForMenu(cmd uintptr) action {
	switch cmd {
	case idOpen:
		return actOpen
	case idExit:
		return actExit
	}
	return actNone
}

// failureBody is the balloon text after a failed open. chatpipe errors are
// written for end users; an empty one still gets a readable message.
func failureBody(lastErr string) string {
	if lastErr == "" {
		return "NodeLink Support could not open."
	}
	return lastErr
}

// pickIcoEntry parses a .ico container and returns the byte range of the image
// whose width best matches want (0-width means 256). It is pure so it can be
// unit-tested against the embedded asset.
func pickIcoEntry(data []byte, want int) (offset, size uint32, err error) {
	if len(data) < 6 {
		return 0, 0, ErrUnsupported
	}
	if binary.LittleEndian.Uint16(data[0:2]) != 0 || binary.LittleEndian.Uint16(data[2:4]) != 1 {
		return 0, 0, ErrUnsupported
	}
	count := int(binary.LittleEndian.Uint16(data[4:6]))
	if count == 0 || len(data) < 6+count*16 {
		return 0, 0, ErrUnsupported
	}
	best := -1
	bestScore := 1 << 30
	for i := 0; i < count; i++ {
		e := 6 + i*16
		w := int(data[e])
		if w == 0 {
			w = 256
		}
		off := binary.LittleEndian.Uint32(data[e+12 : e+16])
		sz := binary.LittleEndian.Uint32(data[e+8 : e+12])
		if off == 0 || sz == 0 || uint64(off)+uint64(sz) > uint64(len(data)) {
			continue
		}
		score := w - want
		if score < 0 {
			score = -score
		}
		if score < bestScore {
			bestScore = score
			best = i
			offset = off
			size = sz
		}
	}
	if best < 0 {
		return 0, 0, ErrUnsupported
	}
	return offset, size, nil
}
