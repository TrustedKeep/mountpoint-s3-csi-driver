// Package tlsprovider materializes TLS material (CA bundle and client cert/key) delivered
// via a CSI nodePublishSecretRef into files on disk that the Mountpoint Pod can read, and
// injects the corresponding --ca-bundle / --client-cert / --client-key flags into the
// arguments passed to `mount-s3`.
//
// The Secret data is delivered to the CSI driver by kubelet in the NodePublishVolume request's
// Secrets field. Recognized keys follow the conventional Kubernetes Secret schema:
//
//	ca.crt   -> --ca-bundle
//	tls.crt  -> --client-cert
//	tls.key  -> --client-key
//
// tls.crt and tls.key must appear together (or neither). ca.crt is independent and may be
// supplied on its own for server-only TLS validation against a private CA.
package tlsprovider

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/google/renameio"

	"github.com/awslabs/mountpoint-s3-csi-driver/pkg/mountpoint"
)

// Secret keys recognized in `req.Secrets` for nodePublishSecretRef-delivered TLS material.
const (
	SecretKeyCABundle   = "ca.crt"
	SecretKeyClientCert = "tls.crt"
	SecretKeyClientKey  = "tls.key"
)

// On-disk filenames written under [ProvideContext.WritePath]. Kept identical to the Secret
// key names so the layout is self-describing on the node.
const (
	FileNameCABundle   = SecretKeyCABundle
	FileNameClientCert = SecretKeyClientCert
	FileNameClientKey  = SecretKeyClientKey
)

// TLSFilePerm is the permission used for PEM material on disk.
// Owner+group read/write; the Mountpoint Pod runs as a non-root user in the same fsGroup.
const TLSFilePerm = fs.FileMode(0640)

// TLSDirPerm is the permission used for the tls/ directory.
const TLSDirPerm = fs.FileMode(0750)

// A ProvideContext contains the parameters needed to materialize TLS material for a mount.
//
// WritePath and EnvPath follow the same convention as credentialprovider.ProvideContext:
// the CSI driver and the Mountpoint Pod see the same files at different paths, so the
// driver writes to WritePath and emits Mountpoint flags pointing at EnvPath.
type ProvideContext struct {
	// Secrets is the raw map delivered via NodePublishVolumeRequest.Secrets.
	Secrets map[string]string

	// WritePath is the host-side directory the PEM files are written into.
	WritePath string
	// EnvPath is the Mountpoint-Pod-side directory used to construct mount-s3 flag values.
	EnvPath string
}

// SetWriteAndEnvPath sets WritePath and EnvPath on ctx.
func (ctx *ProvideContext) SetWriteAndEnvPath(writePath, envPath string) {
	ctx.WritePath = writePath
	ctx.EnvPath = envPath
}

// A CleanupContext contains the parameters needed to remove previously written TLS files.
type CleanupContext struct {
	// WritePath is the host-side directory the PEM files were written to in Provide.
	WritePath string
}

// A Provider materializes TLS Secret data into files on disk.
type Provider struct{}

// ProviderInterface is the interface satisfied by [Provider]. Defined for testability.
type ProviderInterface interface {
	Provide(provideCtx ProvideContext, args mountpoint.Args) error
	Cleanup(cleanupCtx CleanupContext) error
}

// New returns a new [Provider].
func New() *Provider {
	return &Provider{}
}

// HasTLSMaterial reports whether the given Secrets map contains any recognized TLS key.
// Callers use this to detect whether a TLS-aware code path needs to run at all.
func HasTLSMaterial(secrets map[string]string) bool {
	if len(secrets) == 0 {
		return false
	}
	_, hasCA := secrets[SecretKeyCABundle]
	_, hasCert := secrets[SecretKeyClientCert]
	_, hasKey := secrets[SecretKeyClientKey]
	return hasCA || hasCert || hasKey
}

// TLSArgKeys returns the mount-s3 flag keys that this provider may set on Args.
// Exposed for callers that need to detect conflicts with user-supplied mountOptions.
func TLSArgKeys() []string {
	return []string{mountpoint.ArgCABundle, mountpoint.ArgClientCert, mountpoint.ArgClientKey}
}

// Provide validates the TLS material in provideCtx.Secrets, writes PEM files into
// provideCtx.WritePath, and Sets the corresponding flags on args using paths rooted at
// provideCtx.EnvPath. If no TLS keys are present in Secrets, Provide is a no-op.
//
// Returns an error if exactly one of tls.crt or tls.key is present (they must be paired)
// or if any file write fails.
func (p *Provider) Provide(provideCtx ProvideContext, args mountpoint.Args) error {
	if !HasTLSMaterial(provideCtx.Secrets) {
		return nil
	}

	if provideCtx.WritePath == "" || provideCtx.EnvPath == "" {
		return fmt.Errorf("tlsprovider: WritePath and EnvPath must be set before calling Provide")
	}

	caBundle, hasCA := provideCtx.Secrets[SecretKeyCABundle]
	clientCert, hasCert := provideCtx.Secrets[SecretKeyClientCert]
	clientKey, hasKey := provideCtx.Secrets[SecretKeyClientKey]

	if hasCert != hasKey {
		return fmt.Errorf("tlsprovider: %q and %q must be supplied together", SecretKeyClientCert, SecretKeyClientKey)
	}

	if hasCA {
		if err := writePEM(provideCtx.WritePath, FileNameCABundle, caBundle); err != nil {
			return err
		}
		args.Set(mountpoint.ArgCABundle, filepath.Join(provideCtx.EnvPath, FileNameCABundle))
	}

	if hasCert {
		if err := writePEM(provideCtx.WritePath, FileNameClientCert, clientCert); err != nil {
			return err
		}
		if err := writePEM(provideCtx.WritePath, FileNameClientKey, clientKey); err != nil {
			return err
		}
		args.Set(mountpoint.ArgClientCert, filepath.Join(provideCtx.EnvPath, FileNameClientCert))
		args.Set(mountpoint.ArgClientKey, filepath.Join(provideCtx.EnvPath, FileNameClientKey))
	}

	return nil
}

// Cleanup removes any TLS files previously written by Provide for the given CleanupContext.
// Files that don't exist are not treated as errors.
func (p *Provider) Cleanup(cleanupCtx CleanupContext) error {
	if cleanupCtx.WritePath == "" {
		return nil
	}

	var errs []error
	for _, name := range []string{FileNameCABundle, FileNameClientCert, FileNameClientKey} {
		if err := removeIfExists(filepath.Join(cleanupCtx.WritePath, name)); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func writePEM(dir, name, data string) error {
	if data == "" {
		return fmt.Errorf("tlsprovider: refusing to write empty PEM material for %q", name)
	}
	path := filepath.Join(dir, name)
	if err := renameio.WriteFile(path, []byte(data), TLSFilePerm); err != nil {
		return fmt.Errorf("tlsprovider: failed to write %q: %w", path, err)
	}
	return nil
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("tlsprovider: failed to remove %q: %w", path, err)
	}
	return nil
}
