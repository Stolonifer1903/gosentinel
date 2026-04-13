package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// WriteJSON renders the scan result as a JSON file to outPath.
func WriteJSON(result *ScanResult, outPath string) error {
	// Pre-calculate severity counts if not already done
	if result.SeverityCounts == nil {
		result.SeverityCounts = make(map[string]int)
		for _, f := range result.Findings {
			result.SeverityCounts[string(f.Severity)]++
		}
	}

	// Ensure the output directory exists.
	if dir := filepath.Dir(outPath); dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating output directory: %w", err)
		}
	}

	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("creating report file: %w", err)
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}

	return nil
}
