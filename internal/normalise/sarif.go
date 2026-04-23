package normalise

import (
	"io"

	"github.com/block/benchmrk/internal/sarif"
)

// SarifConverter implements Converter for native SARIF 2.1.0 output.
// This is a passthrough that delegates to the existing sarif.Parse().
type SarifConverter struct{}

func (s *SarifConverter) Convert(r io.Reader) (*sarif.SarifReport, error) {
	return sarif.Parse(r)
}
