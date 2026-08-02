//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import "context"

// localAdminsScript enumerates the built-in Administrators group by its
// well-known SID and emits one record per member. ErrorActionPreference=Stop
// makes a partial failure — for example an unresolvable domain member because a
// domain controller is unreachable — surface as a non-zero exit, so the section
// is reported unavailable rather than as a misleadingly short membership.
const localAdminsScript = `$ErrorActionPreference = 'Stop'
$members = Get-LocalGroupMember -SID '` + LocalAdminsGroupSID + `'
$out = foreach ($m in $members) {
  [pscustomobject]@{
    name             = [string]$m.Name
    sid              = [string]$m.SID.Value
    object_class     = [string]$m.ObjectClass
    principal_source = [string]$m.PrincipalSource
  }
}
@($out) | ConvertTo-Json -Compress -Depth 3`

// collectLocalAdministrators reads Administrators membership and hands it to the
// interpreter. Only the read lives here; classification and bounding are in
// local_administrators.go and are tested on any platform. Any execution error
// (including a directory that cannot resolve a member) yields StatusUnavailable
// so a transient outage is operator-visible and never mistaken for an empty
// group.
func collectLocalAdministrators(ctx context.Context) (map[string]any, string) {
	rows, err := psJSON(ctx, localAdminsScript)
	if err != nil {
		return nil, StatusUnavailable
	}

	raw := make([]RawLocalAdmin, 0, len(rows))
	for _, row := range rows {
		str := func(key string) string {
			value, _ := row[key].(string)
			return value
		}
		raw = append(raw, RawLocalAdmin{
			Name:            str("name"),
			SID:             str("sid"),
			ObjectClass:     str("object_class"),
			PrincipalSource: str("principal_source"),
		})
	}
	return NormalizeLocalAdmins(raw)
}
