package test

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// T11 (I10): gitleaks finds nothing in the working tree. If gitleaks is
// missing the test skips locally but fails when CI is set.
func TestNoSecretsInTree(t *testing.T) {
	bin, err := exec.LookPath("gitleaks")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("gitleaks not installed in CI")
		}
		t.Skip("gitleaks not installed")
	}
	report := filepath.Join(t.TempDir(), "report.json")
	cmd := exec.Command(bin, "detect", "--no-git", "--source", repoRoot(t), "--redact", "--no-banner",
		"--report-format", "json", "--report-path", report)
	out, err := cmd.CombinedOutput()
	b, rerr := os.ReadFile(report)
	if rerr != nil {
		t.Fatalf("no report: %v\n%s", rerr, out)
	}
	var findings []map[string]any
	_ = json.Unmarshal(b, &findings)
	if err != nil || len(findings) != 0 {
		for _, f := range findings {
			t.Errorf("finding: %v in %v", f["RuleID"], f["File"])
		}
		t.Fatalf("gitleaks: %v\n%s", err, out)
	}
	t.Logf("gitleaks: 0 findings (%s)", strings.TrimSpace(lastLine(string(out))))
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}

type pkgInfo struct {
	ImportPath string
	Dir        string
	GoFiles    []string
	Module     *struct{ Path string }
}

func goList(t *testing.T, args ...string) []pkgInfo {
	cmd := exec.Command("go", append([]string{"list", "-json"}, args...)...)
	cmd.Dir = repoRoot(t)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	var pkgs []pkgInfo
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for dec.More() {
		var p pkgInfo
		if err := dec.Decode(&p); err != nil {
			t.Fatal(err)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

// Secret-bearing identifiers the coordinator must never reference (I3).
var forbiddenSelectors = map[string]bool{
	"tcrsa.KeyShare":     true,
	"tcrsa.KeyShareList": true,
	"tcrsa.NewKey":       true,
	"tcrsa.KeyMetaArgs":  true,
}

var forbiddenPkgs = []string{
	"frost-k8s-threshold-signing/internal/keyshare",
	"frost-k8s-threshold-signing/internal/dealer",
	"frost-k8s-threshold-signing/internal/signer",
	"frost-k8s-threshold-signing/internal/testutil",
	"github.com/bytemare/",
}

var sharePath = regexp.MustCompile(`share-[0-9*{%]|share\.json|SHARE_FILE`)

// T12 (I3): the coordinator binary's dependency graph contains no secret
// share package, and its module-local sources never reference tcrsa's
// secret types or a share file path.
func TestCoordinatorHasNoSecretTypes(t *testing.T) {
	deps := goList(t, "-deps", "./cmd/grpc-proxy")
	var local []pkgInfo
	for _, p := range deps {
		for _, f := range forbiddenPkgs {
			if strings.HasPrefix(p.ImportPath, f) {
				t.Fatalf("coordinator depends on %s", p.ImportPath)
			}
		}
		if p.Module != nil && p.Module.Path == "frost-k8s-threshold-signing" {
			local = append(local, p)
		}
	}
	fset := token.NewFileSet()
	files := 0
	for _, p := range local {
		for _, name := range p.GoFiles {
			path := filepath.Join(p.Dir, name)
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			files++
			ast.Inspect(f, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.SelectorExpr:
					if id, ok := x.X.(*ast.Ident); ok && forbiddenSelectors[id.Name+"."+x.Sel.Name] {
						t.Errorf("%s: coordinator dependency references %s.%s", fset.Position(x.Pos()), id.Name, x.Sel.Name)
					}
				case *ast.BasicLit:
					if x.Kind == token.STRING && sharePath.MatchString(x.Value) {
						t.Errorf("%s: coordinator dependency mentions share file path %s", fset.Position(x.Pos()), x.Value)
					}
				}
				return true
			})
		}
	}
	var names []string
	for _, p := range local {
		names = append(names, strings.TrimPrefix(p.ImportPath, "frost-k8s-threshold-signing/"))
	}
	t.Logf("coordinator module packages scanned (%d files): %v", files, names)

	// The test-only malicious signer is excluded from default builds.
	for _, p := range goList(t, "./internal/signer") {
		for _, f := range p.GoFiles {
			if strings.Contains(f, "testmalicious") {
				t.Fatalf("default build of internal/signer includes %s", f)
			}
		}
	}
	for _, b := range []string{"./cmd/signer", "./cmd/dealer"} {
		for _, p := range goList(t, "-deps", b) {
			if strings.HasPrefix(p.ImportPath, "github.com/bytemare/") || strings.HasSuffix(p.ImportPath, "/internal/testutil") {
				t.Fatalf("%s depends on %s", b, p.ImportPath)
			}
		}
	}
}
