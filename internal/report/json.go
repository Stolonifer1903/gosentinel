package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Stolonifer1903/gosentinel/internal/scanner"
)

// WriteJSON renders the scan result as a JSON file to outPath.
func WriteJSON(result *ScanResult, outPath string) error {
	prepareScanResult(result)

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

func prepareScanResult(result *ScanResult) {
	result.SeverityCounts = newSeverityCounts()

	for _, f := range result.Findings {
		result.SeverityCounts[string(f.Severity)]++
	}
}

func newSeverityCounts() map[string]int {
	return map[string]int{
		string(scanner.Critical): 0,
		string(scanner.High):     0,
		string(scanner.Medium):   0,
		string(scanner.Low):      0,
		string(scanner.Info):     0,
	}
}
