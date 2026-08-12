// SPDX-License-Identifier: AGPL-3.0-only
package selfupdate

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// versionPattern accepts the release-version shape this project stamps into
// binaries: MAJOR.MINOR.PATCH with an optional dash-separated prerelease tag
// (e.g. 0.1.5, 0.2.0-rc.1). Build metadata is deliberately not accepted: two
// artifacts that differ only in build metadata would compare equal, which is
// not a safe basis for an anti-rollback decision.
var versionPattern = regexp.MustCompile(`^(\d{1,6})\.(\d{1,6})\.(\d{1,6})(?:-([0-9A-Za-z.-]{1,64}))?$`)

// Version is a parsed, comparable agent build version.
type Version struct {
	Major, Minor, Patch int
	Prerelease          string
	Raw                 string
}

// ParseVersion parses a stamped agent version and fails closed on anything it
// cannot order deterministically.
func ParseVersion(raw string) (Version, error) {
	match := versionPattern.FindStringSubmatch(raw)
	if match == nil {
		return Version{}, fmt.Errorf("version %q is not a supported MAJOR.MINOR.PATCH[-prerelease] value", raw)
	}
	major, _ := strconv.Atoi(match[1])
	minor, _ := strconv.Atoi(match[2])
	patch, _ := strconv.Atoi(match[3])
	return Version{Major: major, Minor: minor, Patch: patch, Prerelease: match[4], Raw: raw}, nil
}

// Compare returns -1, 0, or 1 for a < b, a == b, a > b. Ordering follows semver
// precedence: numeric fields first, then "a prerelease is lower than the
// release it precedes", then dot-separated prerelease identifiers.
func Compare(a, b Version) int {
	for _, pair := range [][2]int{
		{a.Major, b.Major}, {a.Minor, b.Minor}, {a.Patch, b.Patch},
	} {
		if pair[0] != pair[1] {
			if pair[0] < pair[1] {
				return -1
			}
			return 1
		}
	}
	if a.Prerelease == b.Prerelease {
		return 0
	}
	if a.Prerelease == "" {
		return 1
	}
	if b.Prerelease == "" {
		return -1
	}
	return comparePrerelease(a.Prerelease, b.Prerelease)
}

func comparePrerelease(a, b string) int {
	left := strings.Split(a, ".")
	right := strings.Split(b, ".")
	for i := 0; i < len(left) && i < len(right); i++ {
		if left[i] == right[i] {
			continue
		}
		leftNum, leftErr := strconv.Atoi(left[i])
		rightNum, rightErr := strconv.Atoi(right[i])
		switch {
		case leftErr == nil && rightErr == nil:
			if leftNum < rightNum {
				return -1
			}
			return 1
		case leftErr == nil:
			// Numeric identifiers always have lower precedence than alphanumeric.
			return -1
		case rightErr == nil:
			return 1
		case left[i] < right[i]:
			return -1
		default:
			return 1
		}
	}
	switch {
	case len(left) < len(right):
		return -1
	case len(left) > len(right):
		return 1
	default:
		return 0
	}
}
