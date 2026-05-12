package node

import (
	"testing"

	"github.com/container-storage-interface/spec/lib/go/csi"

	"github.com/awslabs/mountpoint-s3-csi-driver/pkg/driver/node/volumecontext"
)

// Regression guard: logSafeNodePublishVolumeRequest must never include the Secrets map
// (kubelet delivers TLS material and other sensitive bearer tokens here) and must continue
// to strip the service-account-tokens volume-context key.
func TestLogSafeNodePublishVolumeRequest_StripsSecretsAndSAToken(t *testing.T) {
	req := &csi.NodePublishVolumeRequest{
		VolumeId: "vol-1",
		Secrets: map[string]string{
			"ca.crt":  "ca",
			"tls.crt": "cert",
			"tls.key": "key",
		},
		VolumeContext: map[string]string{
			"bucketName":                            "b",
			volumecontext.CSIServiceAccountTokens:   "should-be-stripped",
		},
	}

	safe := logSafeNodePublishVolumeRequest(req)

	if safe.Secrets != nil {
		t.Errorf("Secrets must not be carried through to logs; got %v", safe.Secrets)
	}
	if _, present := safe.VolumeContext[volumecontext.CSIServiceAccountTokens]; present {
		t.Errorf("ServiceAccountTokens must be stripped from VolumeContext; got %v", safe.VolumeContext)
	}
	if safe.VolumeContext["bucketName"] != "b" {
		t.Errorf("non-sensitive VolumeContext entries must be preserved; got %v", safe.VolumeContext)
	}
}
