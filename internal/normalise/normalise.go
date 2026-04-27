package normalise

import (
	"fmt"
	"io"
	"sync"

	"github.com/block/benchmrk/internal/sarif"
)

// Converter converts scanner output in a specific format to a SARIF report.
type Converter interface {
	// Convert reads scanner output and produces a SARIF report.
	Convert(r io.Reader) (*sarif.SarifReport, error)
}

// Registry maps format names to converters.
type Registry struct {
	mu         sync.RWMutex
	converters map[string]Converter
}

// NewRegistry creates a new converter registry.
func NewRegistry() *Registry {
	return &Registry{
		converters: make(map[string]Converter),
	}
}

// Register adds a converter for the given format name.
func (reg *Registry) Register(format string, c Converter) {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	reg.converters[format] = c
}

// Get returns the converter for the given format name.
func (reg *Registry) Get(format string) (Converter, bool) {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	c, ok := reg.converters[format]
	return c, ok
}

// Convert looks up the converter for the given format and runs it.
func (reg *Registry) Convert(format string, r io.Reader) (*sarif.SarifReport, error) {
	c, ok := reg.Get(format)
	if !ok {
		return nil, fmt.Errorf("no converter registered for format %q", format)
	}
	return c.Convert(r)
}

// Formats returns the list of registered format names.
func (reg *Registry) Formats() []string {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	names := make([]string, 0, len(reg.converters))
	for name := range reg.converters {
		names = append(names, name)
	}
	return names
}
