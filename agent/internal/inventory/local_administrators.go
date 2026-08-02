// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import (
	"sort"
	"strings"
)

// LocalAdminsGroupSID is the well-known, localization-independent SID of the
// built-in Administrators group. The collector resolves membership by this SID
// rather than the display name "Administrators", which is localized and
// renameable, so the section behaves identically on non-English Windows.
const LocalAdminsGroupSID = "S-1-5-32-544"

// MaxLocalAdminMembers mirrors the server's MAX_LOCAL_ADMIN_MEMBERS. A correctly
// managed Administrators group is small; the agent trims to this and reports
// StatusPartial, since the server rejects anything larger.
const MaxLocalAdminMembers = 256

// Identity-origin values for a member. These mirror the server's
// LocalAdminIdentityType exactly.
const (
	IdentityLocal   = "local"
	IdentityDomain  = "domain"
	IdentityAzureAD = "azuread"
	IdentityUnknown = "unknown"
)

// Principal-class values for a member. These mirror the server's
// LocalAdminPrincipalClass exactly.
const (
	PrincipalUser    = "user"
	PrincipalGroup   = "group"
	PrincipalUnknown = "unknown"
)

// RawLocalAdmin is one Administrators member as read from the endpoint, before
// normalization. Keeping the raw shape separate from the wire shape lets the
// classification and bounding be tested on any platform.
type RawLocalAdmin struct {
	Name            string `json:"name"`
	SID             string `json:"sid"`
	ObjectClass     string `json:"object_class"`
	PrincipalSource string `json:"principal_source"`
}

// classifyIdentityType maps a Windows PrincipalSource value to an Identity*
// constant. Anything unrecognized is "unknown" so a member's trust origin is
// never guessed.
func classifyIdentityType(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "local":
		return IdentityLocal
	case "activedirectory":
		return IdentityDomain
	case "azuread":
		return IdentityAzureAD
	default:
		// "microsoftaccount", "unknown", "", or any future value.
		return IdentityUnknown
	}
}

// classifyPrincipalClass maps a Windows ObjectClass value to a Principal*
// constant.
func classifyPrincipalClass(objectClass string) string {
	switch strings.ToLower(strings.TrimSpace(objectClass)) {
	case "user":
		return PrincipalUser
	case "group":
		return PrincipalGroup
	default:
		return PrincipalUnknown
	}
}

// NormalizeLocalAdmins turns raw member rows into the wire payload and the
// section status. Rows with no name are dropped (a nameless principal is an
// artifact, not an account), members over the cap are trimmed to StatusPartial,
// and the result is sorted so the section's content hash is stable between runs
// — endpoint enumeration order is not, and an unsorted list would re-upload the
// unchanged group on every collection.
func NormalizeLocalAdmins(rows []RawLocalAdmin) (map[string]any, string) {
	members := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		name := strings.TrimSpace(row.Name)
		if name == "" {
			continue
		}
		member := map[string]any{
			"name":            name,
			"identity_type":   classifyIdentityType(row.PrincipalSource),
			"principal_class": classifyPrincipalClass(row.ObjectClass),
		}
		if sid := strings.TrimSpace(row.SID); sid != "" {
			member["sid"] = sid
		}
		members = append(members, member)
	}

	sort.Slice(members, func(i, j int) bool {
		li, _ := members[i]["name"].(string)
		ri, _ := members[j]["name"].(string)
		if !strings.EqualFold(li, ri) {
			return strings.ToLower(li) < strings.ToLower(ri)
		}
		lsid, _ := members[i]["sid"].(string)
		rsid, _ := members[j]["sid"].(string)
		return lsid < rsid
	})

	status := StatusOK
	if len(members) > MaxLocalAdminMembers {
		members = members[:MaxLocalAdminMembers]
		status = StatusPartial
	}
	return map[string]any{"members": members}, status
}
