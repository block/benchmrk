package normalise

// NewDefaultRegistry creates a registry pre-loaded with all built-in converters.
func NewDefaultRegistry() *Registry {
	reg := NewRegistry()
	reg.Register("sarif", &SarifConverter{})
	reg.Register("semgrep-json", &SemgrepConverter{})
	return reg
}
