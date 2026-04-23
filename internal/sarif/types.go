package sarif

// SarifReport represents the root SARIF 2.1.0 document.
type SarifReport struct {
	Schema  string `json:"$schema,omitempty"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

// Run represents a single analysis run within a SARIF report.
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results,omitempty"`
}

// Tool contains information about the analysis tool.
type Tool struct {
	Driver ToolComponent `json:"driver"`
}

// ToolComponent describes an analysis tool or plugin.
type ToolComponent struct {
	Name            string                `json:"name"`
	Version         string                `json:"version,omitempty"`
	InformationURI  string                `json:"informationUri,omitempty"`
	Rules           []ReportingDescriptor `json:"rules,omitempty"`
	SemanticVersion string                `json:"semanticVersion,omitempty"`
}

// ReportingDescriptor describes a rule used by the analysis tool.
type ReportingDescriptor struct {
	ID               string                            `json:"id"`
	Name             string                            `json:"name,omitempty"`
	ShortDescription *Message                          `json:"shortDescription,omitempty"`
	FullDescription  *Message                          `json:"fullDescription,omitempty"`
	HelpURI          string                            `json:"helpUri,omitempty"`
	Help             *MultiformatMessage               `json:"help,omitempty"`
	Properties       *PropertyBag                      `json:"properties,omitempty"`
	DefaultConfig    *ReportingConfig                  `json:"defaultConfiguration,omitempty"`
	Relationships    []ReportingDescriptorRelationship `json:"relationships,omitempty"`
}

// ReportingDescriptorRelationship describes a relationship between a rule and a taxonomy entry.
type ReportingDescriptorRelationship struct {
	Target *ReportingDescriptorReference `json:"target,omitempty"`
}

// ReportingDescriptorReference identifies a reporting descriptor (e.g. a CWE taxonomy entry).
type ReportingDescriptorReference struct {
	ID            string            `json:"id,omitempty"`
	ToolComponent *ToolComponentRef `json:"toolComponent,omitempty"`
}

// ToolComponentRef identifies a tool component by name or index.
type ToolComponentRef struct {
	Name string `json:"name,omitempty"`
}

// ReportingConfig describes the default configuration for a rule.
type ReportingConfig struct {
	Level string `json:"level,omitempty"`
}

// PropertyBag is a set of custom properties.
type PropertyBag struct {
	Tags      []string `json:"tags,omitempty"`
	CWE       string   `json:"cwe,omitempty"`
	Precision string   `json:"precision,omitempty"`
	Security  string   `json:"security-severity,omitempty"`
}

// MultiformatMessage provides a message in multiple formats.
type MultiformatMessage struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

// Result represents a single finding from the analysis.
type Result struct {
	RuleID              string            `json:"ruleId,omitempty"`
	RuleIndex           *int              `json:"ruleIndex,omitempty"`
	Level               string            `json:"level,omitempty"`
	Message             Message           `json:"message"`
	Locations           []Location        `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

// Message contains a human-readable message.
type Message struct {
	Text string `json:"text,omitempty"`
}

// Location describes a location where a result was detected.
type Location struct {
	PhysicalLocation *PhysicalLocation `json:"physicalLocation,omitempty"`
}

// PhysicalLocation describes a physical location within an artifact.
type PhysicalLocation struct {
	ArtifactLocation *ArtifactLocation `json:"artifactLocation,omitempty"`
	Region           *Region           `json:"region,omitempty"`
	ContextRegion    *Region           `json:"contextRegion,omitempty"`
}

// ArtifactLocation describes the location of an artifact.
type ArtifactLocation struct {
	URI       string `json:"uri,omitempty"`
	URIBaseID string `json:"uriBaseId,omitempty"`
	Index     *int   `json:"index,omitempty"`
}

// Region describes a region within an artifact.
type Region struct {
	StartLine   *int             `json:"startLine,omitempty"`
	StartColumn *int             `json:"startColumn,omitempty"`
	EndLine     *int             `json:"endLine,omitempty"`
	EndColumn   *int             `json:"endColumn,omitempty"`
	Snippet     *ArtifactContent `json:"snippet,omitempty"`
}

// ArtifactContent describes the content of an artifact.
type ArtifactContent struct {
	Text string `json:"text,omitempty"`
}

// Finding represents a flattened, normalized finding extracted from SARIF.
type Finding struct {
	RuleID      string
	RuleName    string // human-readable rule title: reportingDescriptor.name or .shortDescription.text
	FilePath    string
	StartLine   int
	EndLine     int
	CWE         string
	Severity    string
	Message     string
	Snippet     string
	Fingerprint string
}
