package keyring

// Option configures one [Open] call.
type Option struct {
	// Service namespaces credentials during backend discovery.
	Service string
	// Keyringer bypasses backend discovery when non-nil.
	Keyringer Keyringer
	// FallbackDir explicitly permits filesystem fallback at this location.
	FallbackDir string
	// Backends overrides the default backend order when non-empty.
	Backends []Backend
}

func mergeOptions(options ...*Option) Option {
	var merged Option
	for _, option := range options {
		if option.Service != "" {
			merged.Service = option.Service
		}
		if option.Keyringer != nil {
			merged.Keyringer = option.Keyringer
		}
		if option.FallbackDir != "" {
			merged.FallbackDir = option.FallbackDir
		}
		if len(option.Backends) != 0 {
			merged.Backends = option.Backends
		}
	}
	return merged
}
