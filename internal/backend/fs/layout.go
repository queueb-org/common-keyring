package fs

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
)

const (
	layoutVersion = "v1"
	serviceDomain = "service\x00"
	keyDomain     = "key\x00"
)

type layout struct {
	serviceID string
}

func newLayout(service string) layout {
	return layout{serviceID: identifier(serviceDomain, service)}
}

func (l layout) servicePath() string {
	return filepath.Join(layoutVersion, l.serviceID)
}

func (l layout) keyPath(key string) string {
	return filepath.Join(l.servicePath(), identifier(keyDomain, key))
}

func identifier(domain, value string) string {
	digest := sha256.Sum256([]byte(domain + value))
	return hex.EncodeToString(digest[:])
}
