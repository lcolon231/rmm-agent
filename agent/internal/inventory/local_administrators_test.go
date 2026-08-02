// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import (
	"fmt"
	"testing"
)

func TestNormalizeLocalAdminsClassifiesAndSorts(t *testing.T) {
	rows := []RawLocalAdmin{
		{Name: "CONTOSO\\Domain Admins", SID: "S-1-5-21-2-512", ObjectClass: "Group", PrincipalSource: "ActiveDirectory"},
		{Name: "BUILTIN\\Administrator", SID: "S-1-5-21-1-500", ObjectClass: "User", PrincipalSource: "Local"},
		{Name: "AzureAD\\alice", SID: "S-1-12-1-1", ObjectClass: "User", PrincipalSource: "AzureAD"},
	}
	payload, status := NormalizeLocalAdmins(rows)
	if status != StatusOK {
		t.Fatalf("status = %q, want ok", status)
	}
	members, _ := payload["members"].([]map[string]any)
	if len(members) != 3 {
		t.Fatalf("want 3 members, got %d", len(members))
	}
	// Sorted case-insensitively by name for a stable content hash.
	wantOrder := []struct {
		name     string
		identity string
		class    string
	}{
		{"AzureAD\\alice", IdentityAzureAD, PrincipalUser},
		{"BUILTIN\\Administrator", IdentityLocal, PrincipalUser},
		{"CONTOSO\\Domain Admins", IdentityDomain, PrincipalGroup},
	}
	for i, w := range wantOrder {
		if members[i]["name"] != w.name {
			t.Errorf("member %d name = %v, want %q", i, members[i]["name"], w.name)
		}
		if members[i]["identity_type"] != w.identity {
			t.Errorf("member %d identity = %v, want %q", i, members[i]["identity_type"], w.identity)
		}
		if members[i]["principal_class"] != w.class {
			t.Errorf("member %d class = %v, want %q", i, members[i]["principal_class"], w.class)
		}
	}
}

// The content hash is computed over the payload, so the same membership in a
// different enumeration order must produce byte-identical output.
func TestNormalizeLocalAdminsIsOrderStable(t *testing.T) {
	a := []RawLocalAdmin{
		{Name: "b", SID: "S-2", ObjectClass: "User", PrincipalSource: "Local"},
		{Name: "a", SID: "S-1", ObjectClass: "User", PrincipalSource: "Local"},
	}
	b := []RawLocalAdmin{
		{Name: "a", SID: "S-1", ObjectClass: "User", PrincipalSource: "Local"},
		{Name: "b", SID: "S-2", ObjectClass: "User", PrincipalSource: "Local"},
	}
	pa, _ := NormalizeLocalAdmins(a)
	pb, _ := NormalizeLocalAdmins(b)
	ha, err := ContentHash(pa)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := ContentHash(pb)
	if err != nil {
		t.Fatal(err)
	}
	if ha != hb {
		t.Fatalf("content hash differs by input order: %s vs %s", ha, hb)
	}
}

func TestNormalizeLocalAdminsDropsNamelessAndOmitsBlankSID(t *testing.T) {
	rows := []RawLocalAdmin{
		{Name: "  ", SID: "S-1", ObjectClass: "User", PrincipalSource: "Local"},
		{Name: "keep", SID: "", ObjectClass: "User", PrincipalSource: "Local"},
	}
	payload, _ := NormalizeLocalAdmins(rows)
	members, _ := payload["members"].([]map[string]any)
	if len(members) != 1 {
		t.Fatalf("nameless row should be dropped, got %d members", len(members))
	}
	if _, present := members[0]["sid"]; present {
		t.Error("blank SID should be omitted, not stored empty")
	}
}

func TestNormalizeLocalAdminsUnknownClassification(t *testing.T) {
	rows := []RawLocalAdmin{
		{Name: "x", SID: "S-1", ObjectClass: "Computer", PrincipalSource: "MicrosoftAccount"},
	}
	payload, _ := NormalizeLocalAdmins(rows)
	members, _ := payload["members"].([]map[string]any)
	// An unrecognized source/class must never be guessed into a real value.
	if members[0]["identity_type"] != IdentityUnknown {
		t.Errorf("identity = %v, want unknown", members[0]["identity_type"])
	}
	if members[0]["principal_class"] != PrincipalUnknown {
		t.Errorf("class = %v, want unknown", members[0]["principal_class"])
	}
}

func TestNormalizeLocalAdminsBoundsToPartial(t *testing.T) {
	rows := make([]RawLocalAdmin, 0, MaxLocalAdminMembers+10)
	for i := 0; i < MaxLocalAdminMembers+10; i++ {
		rows = append(rows, RawLocalAdmin{
			Name:            fmt.Sprintf("user-%04d", i),
			SID:             fmt.Sprintf("S-1-5-21-%d", i),
			ObjectClass:     "User",
			PrincipalSource: "Local",
		})
	}
	payload, status := NormalizeLocalAdmins(rows)
	if status != StatusPartial {
		t.Fatalf("status = %q, want partial", status)
	}
	members, _ := payload["members"].([]map[string]any)
	if len(members) != MaxLocalAdminMembers {
		t.Fatalf("members = %d, want cap %d", len(members), MaxLocalAdminMembers)
	}
}

func TestNormalizeLocalAdminsEmptyIsOK(t *testing.T) {
	payload, status := NormalizeLocalAdmins(nil)
	if status != StatusOK {
		t.Fatalf("status = %q, want ok", status)
	}
	members, _ := payload["members"].([]map[string]any)
	if len(members) != 0 {
		t.Fatalf("want empty members, got %d", len(members))
	}
}
