// SPDX-License-Identifier: AGPL-3.0-only
package chattray

import "testing"

func TestErrUnsupportedHasMessage(t *testing.T) {
	if ErrUnsupported == nil || ErrUnsupported.Error() == "" {
		t.Fatal("ErrUnsupported must carry a message")
	}
}
