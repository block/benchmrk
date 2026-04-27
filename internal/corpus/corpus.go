package corpus

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/block/benchmrk/internal/store"
)

// Common errors
var (
	ErrEmptyName       = errors.New("project name cannot be empty")
	ErrPathNotFound    = errors.New("source path does not exist")
	ErrProjectNotFound = errors.New("project not found")
	ErrDuplicateName   = errors.New("project with this name already exists")
)

// languageExtensions maps file extensions to programming languages
var languageExtensions = map[string]string{
	".go":    "go",
	".java":  "java",
	".py":    "python",
	".js":    "javascript",
	".ts":    "typescript",
	".jsx":   "javascript",
	".tsx":   "typescript",
	".rb":    "ruby",
	".php":   "php",
	".c":     "c",
	".cpp":   "cpp",
	".cc":    "cpp",
	".h":     "c",
	".hpp":   "cpp",
	".cs":    "csharp",
	".rs":    "rust",
	".swift": "swift",
	".kt":    "kotlin",
	".scala": "scala",
	".m":     "objectivec",
	".sql":   "sql",
	".sh":    "bash",
}

// Service provides corpus management operations.
type Service struct {
	store *store.Store
}

// New creates a new corpus Service with the given store.
func New(s *store.Store) *Service {
	return &Service{store: s}
}

// AddProject adds a new project to the corpus.
// If language is empty, it is detected from the source path.
func (s *Service) AddProject(ctx context.Context, name, sourcePath, language, commitSHA string) (*store.CorpusProject, error) {
	if name == "" {
		return nil, ErrEmptyName
	}

	// Check if path exists
	info, err := os.Stat(sourcePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrPathNotFound
		}
		return nil, fmt.Errorf("stat source path: %w", err)
	}

	// Ensure path is absolute
	absPath, err := filepath.Abs(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("get absolute path: %w", err)
	}

	// Check for duplicate name
	_, err = s.store.GetProjectByName(ctx, name)
	if err == nil {
		return nil, ErrDuplicateName
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("check existing project: %w", err)
	}

	// Detect language if not provided
	detectedLanguage := language
	if detectedLanguage == "" && info.IsDir() {
		detectedLanguage = detectLanguage(absPath)
	}

	// Create project record
	project := &store.CorpusProject{
		Name:      name,
		LocalPath: absPath,
	}

	if detectedLanguage != "" {
		project.Language = sql.NullString{String: detectedLanguage, Valid: true}
	}

	if commitSHA != "" {
		project.CommitSHA = sql.NullString{String: commitSHA, Valid: true}
	}

	id, err := s.store.CreateProject(ctx, project)
	if err != nil {
		return nil, fmt.Errorf("create project: %w", err)
	}

	// Fetch and return the created project with all fields populated
	return s.store.GetProject(ctx, id)
}

// ListProjects returns all corpus projects.
func (s *Service) ListProjects(ctx context.Context) ([]store.CorpusProject, error) {
	return s.store.ListProjects(ctx)
}

// ShowProject retrieves a project by name.
func (s *Service) ShowProject(ctx context.Context, name string) (*store.CorpusProject, error) {
	project, err := s.store.GetProjectByName(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrProjectNotFound
	}
	return project, err
}

// RemoveProject deletes a project from the corpus.
func (s *Service) RemoveProject(ctx context.Context, name string) error {
	// Find project by name first
	project, err := s.store.GetProjectByName(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		return ErrProjectNotFound
	}
	if err != nil {
		return fmt.Errorf("get project: %w", err)
	}

	// Delete by ID
	if err := s.store.DeleteProject(ctx, project.ID); err != nil {
		return fmt.Errorf("delete project: %w", err)
	}

	return nil
}

// detectLanguage analyzes files in a directory and returns the most common language.
func detectLanguage(dirPath string) string {
	counts := make(map[string]int)

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		if info.IsDir() {
			// Skip hidden directories and common non-source directories
			name := info.Name()
			if strings.HasPrefix(name, ".") || name == "node_modules" || name == "vendor" || name == "__pycache__" {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if lang, ok := languageExtensions[ext]; ok {
			counts[lang]++
		}
		return nil
	})

	if err != nil {
		return ""
	}

	// Find the most common language
	var maxLang string
	var maxCount int
	for lang, count := range counts {
		if count > maxCount {
			maxLang = lang
			maxCount = count
		}
	}

	return maxLang
}
