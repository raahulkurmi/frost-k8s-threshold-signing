package dealer_test

import (
	"os"
	"path/filepath"
	"testing"

	"frost-k8s-threshold-signing/internal/dealer"
	"frost-k8s-threshold-signing/internal/keyshare"
)

func fakeKey() *dealer.Key {
	k := &dealer.Key{}
	for i := 1; i <= 3; i++ {
		k.Shares = append(k.Shares, &keyshare.File{Version: 1, KID: "kid", SignerIndex: i, Si: "AQID"})
	}
	return k
}

// TestPrepareOutputDir (audit E-4): only a private directory is used for key
// output; a missing one is created 0700.
func TestPrepareOutputDir(t *testing.T) {
	base := t.TempDir()
	mk := func(name string, mode os.FileMode) string {
		p := filepath.Join(base, name)
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for name, dir := range map[string]string{"0700": mk("private", 0o700), "0755": mk("readable", 0o755)} {
		if err := dealer.PrepareOutputDir(dir); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
	for name, dir := range map[string]string{"0777": mk("world", 0o777), "0770": mk("group", 0o770), "0702": mk("other-w", 0o702)} {
		if err := dealer.PrepareOutputDir(dir); err == nil {
			t.Errorf("%s directory accepted", name)
		}
		if _, err := dealer.WriteShareFiles(dir, fakeKey()); err == nil {
			t.Errorf("%s: shares written", name)
		}
		if m, _ := filepath.Glob(filepath.Join(dir, "share-*.json")); len(m) != 0 {
			t.Errorf("%s: share files left: %v", name, m)
		}
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(mk("target", 0o700), link); err != nil {
		t.Fatal(err)
	}
	if err := dealer.PrepareOutputDir(link); err == nil {
		t.Error("symlinked output directory accepted")
	}
	fresh := filepath.Join(base, "new", "out")
	if err := dealer.PrepareOutputDir(fresh); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(fresh); err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("created directory mode %v, err %v; want 0700", fi.Mode().Perm(), err)
	}
}

// TestWriteShareFilesCleansUpOnFailure (audit E-4): if any share cannot be
// written, the shares already written in that call are removed.
func TestWriteShareFilesCleansUpOnFailure(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, dealer.ShareFileName(2)), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := dealer.WriteShareFiles(dir, fakeKey()); err == nil {
		t.Fatal("WriteShareFiles succeeded over an existing share-2.json")
	}
	if _, err := os.Stat(filepath.Join(dir, dealer.ShareFileName(1))); !os.IsNotExist(err) {
		t.Fatalf("share-1.json left behind after the failed write (stat err %v)", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, dealer.ShareFileName(2))); string(b) != "existing" {
		t.Fatal("the pre-existing file was modified")
	}
}
