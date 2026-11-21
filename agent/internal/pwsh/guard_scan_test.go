// SPDX-License-Identifier: AGPL-3.0-only
package pwsh

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// launchAllowed lists files outside internal/pwsh that may still name a
// PowerShell binary. The Unix executor runs PowerShell 7 for operator scripts,
// which issue #336 left out of scope.
var launchAllowed = map[string]bool{
	"internal/executor/executor_unix.go": true,
}

// findPowerShellLaunches returns "path:line" for each place under root that
// names powershell.exe or pwsh.exe, or passes a bare "powershell"/"pwsh" to
// exec.Command or exec.CommandContext, in production code outside
// internal/pwsh. Test files are skipped: they name the binary as data, such as
// the signed file the Authenticode test verifies.
func findPowerShellLaunches(root string) ([]string, error) {
	var found []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "internal/pwsh" || rel == "testdata" || rel == "vendor" || (rel != "." && strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") || launchAllowed[rel] {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.BasicLit:
				if v, ok := stringValue(n); ok && (strings.EqualFold(v, "powershell.exe") || strings.EqualFold(v, "pwsh.exe")) {
					found = append(found, fmt.Sprintf("%s:%d", rel, fset.Position(n.Pos()).Line))
				}
			case *ast.CallExpr:
				if isExecCommand(n.Fun) {
					for _, arg := range n.Args {
						lit, ok := arg.(*ast.BasicLit)
						if !ok {
							continue
						}
						if v, ok := stringValue(lit); ok && (strings.EqualFold(v, "powershell") || strings.EqualFold(v, "pwsh")) {
							found = append(found, fmt.Sprintf("%s:%d", rel, fset.Position(lit.Pos()).Line))
						}
					}
				}
			}
			return true
		})
		return nil
	})
	sort.Strings(found)
	return found, err
}

func stringValue(lit *ast.BasicLit) (string, bool) {
	if lit.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(lit.Value)
	return v, err == nil
}

func isExecCommand(fun ast.Expr) bool {
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "exec" && (sel.Sel.Name == "Command" || sel.Sel.Name == "CommandContext")
}
