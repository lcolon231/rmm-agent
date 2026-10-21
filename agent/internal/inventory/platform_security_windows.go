//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import (
	"context"
)

func collectBitLocker(ctx context.Context) (map[string]any, string) {
	rows, err := psJSON(ctx, bitlockerScript)
	if err != nil {
		return nil, StatusUnavailable
	}
	row := first(rows)
	if row == nil {
		return nil, StatusUnavailable
	}
	return NormalizeBitLocker(rawBitLockerFromRow(row))
}

func collectSecureBoot(ctx context.Context) (map[string]any, string) {
	rows, err := psJSON(ctx, secureBootScript)
	if err != nil {
		return nil, StatusUnavailable
	}
	row := first(rows)
	if row == nil {
		return nil, StatusUnavailable
	}
	return NormalizeSecureBoot(rawSecureBootFromRow(row))
}

func collectTpm(ctx context.Context) (map[string]any, string) {
	rows, err := psJSON(ctx, tpmScript)
	if err != nil {
		return nil, StatusUnavailable
	}
	row := first(rows)
	if row == nil {
		return nil, StatusUnavailable
	}
	return NormalizeTpm(rawTpmFromRow(row))
}
