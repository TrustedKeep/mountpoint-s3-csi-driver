package tlsprovider_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/awslabs/mountpoint-s3-csi-driver/pkg/driver/node/tlsprovider"
	"github.com/awslabs/mountpoint-s3-csi-driver/pkg/mountpoint"
	"github.com/awslabs/mountpoint-s3-csi-driver/pkg/util/testutil/assert"
)

const (
	testCAPEM   = "-----BEGIN CERTIFICATE-----\nMIITESTCA-----END CERTIFICATE-----\n"
	testCertPEM = "-----BEGIN CERTIFICATE-----\nMIITESTCLIENT-----END CERTIFICATE-----\n"
	testKeyPEM  = "-----BEGIN PRIVATE KEY-----\nMIITESTKEY-----END PRIVATE KEY-----\n"

	envPath = "/comm/tls"
)

func TestHasTLSMaterial(t *testing.T) {
	cases := []struct {
		name    string
		secrets map[string]string
		want    bool
	}{
		{name: "nil secrets", secrets: nil, want: false},
		{name: "empty secrets", secrets: map[string]string{}, want: false},
		{name: "unrelated keys only", secrets: map[string]string{"foo": "bar"}, want: false},
		{name: "ca only", secrets: map[string]string{"ca.crt": testCAPEM}, want: true},
		{name: "client cert only", secrets: map[string]string{"tls.crt": testCertPEM}, want: true},
		{name: "client key only", secrets: map[string]string{"tls.key": testKeyPEM}, want: true},
		{name: "all three", secrets: map[string]string{"ca.crt": testCAPEM, "tls.crt": testCertPEM, "tls.key": testKeyPEM}, want: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equals(t, c.want, tlsprovider.HasTLSMaterial(c.secrets))
		})
	}
}

func TestProvide_NoMaterialIsNoOp(t *testing.T) {
	dir := t.TempDir()
	p := tlsprovider.New()
	args := mountpoint.ParseArgs(nil)

	err := p.Provide(tlsprovider.ProvideContext{
		Secrets:   map[string]string{"unrelated": "x"},
		WritePath: dir,
		EnvPath:   envPath,
	}, args)
	assert.NoError(t, err)
	assert.Equals(t, []string{}, args.SortedList())

	entries, err := os.ReadDir(dir)
	assert.NoError(t, err)
	assert.Equals(t, 0, len(entries))
}

func TestProvide_CABundleOnly(t *testing.T) {
	dir := t.TempDir()
	p := tlsprovider.New()
	args := mountpoint.ParseArgs(nil)

	err := p.Provide(tlsprovider.ProvideContext{
		Secrets:   map[string]string{"ca.crt": testCAPEM},
		WritePath: dir,
		EnvPath:   envPath,
	}, args)
	assert.NoError(t, err)

	// Only --ca-bundle should be set.
	caVal, ok := args.Value(mountpoint.ArgCABundle)
	assert.Equals(t, true, ok)
	assert.Equals(t, filepath.Join(envPath, "ca.crt"), caVal)
	assert.Equals(t, false, args.Has(mountpoint.ArgClientCert))
	assert.Equals(t, false, args.Has(mountpoint.ArgClientKey))

	// File written with the expected content and 0640 perms.
	data, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	assert.NoError(t, err)
	assert.Equals(t, testCAPEM, string(data))
	assertFilePerm(t, filepath.Join(dir, "ca.crt"), 0640)
}

func TestProvide_FullMTLS(t *testing.T) {
	dir := t.TempDir()
	p := tlsprovider.New()
	args := mountpoint.ParseArgs(nil)

	err := p.Provide(tlsprovider.ProvideContext{
		Secrets: map[string]string{
			"ca.crt":  testCAPEM,
			"tls.crt": testCertPEM,
			"tls.key": testKeyPEM,
		},
		WritePath: dir,
		EnvPath:   envPath,
	}, args)
	assert.NoError(t, err)

	caVal, _ := args.Value(mountpoint.ArgCABundle)
	certVal, _ := args.Value(mountpoint.ArgClientCert)
	keyVal, _ := args.Value(mountpoint.ArgClientKey)
	assert.Equals(t, filepath.Join(envPath, "ca.crt"), caVal)
	assert.Equals(t, filepath.Join(envPath, "tls.crt"), certVal)
	assert.Equals(t, filepath.Join(envPath, "tls.key"), keyVal)

	for name, want := range map[string]string{
		"ca.crt":  testCAPEM,
		"tls.crt": testCertPEM,
		"tls.key": testKeyPEM,
	} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		assert.NoError(t, err)
		assert.Equals(t, want, string(got))
	}
}

func TestProvide_CertWithoutKey(t *testing.T) {
	dir := t.TempDir()
	p := tlsprovider.New()
	args := mountpoint.ParseArgs(nil)

	err := p.Provide(tlsprovider.ProvideContext{
		Secrets:   map[string]string{"tls.crt": testCertPEM},
		WritePath: dir,
		EnvPath:   envPath,
	}, args)
	if err == nil {
		t.Fatal("expected error when tls.crt is supplied without tls.key, got nil")
	}
}

func TestProvide_KeyWithoutCert(t *testing.T) {
	dir := t.TempDir()
	p := tlsprovider.New()
	args := mountpoint.ParseArgs(nil)

	err := p.Provide(tlsprovider.ProvideContext{
		Secrets:   map[string]string{"tls.key": testKeyPEM},
		WritePath: dir,
		EnvPath:   envPath,
	}, args)
	if err == nil {
		t.Fatal("expected error when tls.key is supplied without tls.crt, got nil")
	}
}

func TestProvide_MissingPathsReturnsError(t *testing.T) {
	p := tlsprovider.New()
	args := mountpoint.ParseArgs(nil)

	err := p.Provide(tlsprovider.ProvideContext{
		Secrets: map[string]string{"ca.crt": testCAPEM},
	}, args)
	if err == nil {
		t.Fatal("expected error when WritePath/EnvPath are not set, got nil")
	}
}

func TestProvide_OverwritesExistingFiles(t *testing.T) {
	dir := t.TempDir()
	// Pre-populate ca.crt with stale content to ensure renameio overwrites atomically.
	stalePath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(stalePath, []byte("stale"), 0640); err != nil {
		t.Fatalf("seed failed: %v", err)
	}

	p := tlsprovider.New()
	args := mountpoint.ParseArgs(nil)
	err := p.Provide(tlsprovider.ProvideContext{
		Secrets:   map[string]string{"ca.crt": testCAPEM},
		WritePath: dir,
		EnvPath:   envPath,
	}, args)
	assert.NoError(t, err)

	got, err := os.ReadFile(stalePath)
	assert.NoError(t, err)
	assert.Equals(t, testCAPEM, string(got))
}

func TestCleanup_RemovesAllFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"ca.crt", "tls.crt", "tls.key"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0640); err != nil {
			t.Fatalf("seed failed: %v", err)
		}
	}

	p := tlsprovider.New()
	err := p.Cleanup(tlsprovider.CleanupContext{WritePath: dir})
	assert.NoError(t, err)

	for _, name := range []string{"ca.crt", "tls.crt", "tls.key"} {
		assert.FileNotExists(t, filepath.Join(dir, name))
	}
}

func TestCleanup_IsIdempotent(t *testing.T) {
	dir := t.TempDir()
	p := tlsprovider.New()
	// Nothing written; cleanup should still succeed.
	err := p.Cleanup(tlsprovider.CleanupContext{WritePath: dir})
	assert.NoError(t, err)
}

func TestCleanup_EmptyWritePathNoOp(t *testing.T) {
	p := tlsprovider.New()
	err := p.Cleanup(tlsprovider.CleanupContext{})
	assert.NoError(t, err)
}

func assertFilePerm(t *testing.T, path string, want fs.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %q: %v", path, err)
	}
	if info.Mode().Perm() != want {
		t.Errorf("file %q perm = %v, want %v", path, info.Mode().Perm(), want)
	}
}
