package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// ExportRecord is the shape written to the JSON export file.
type ExportRecord struct {
	ExportedAt string  `json:"exported_at"`
	Events     []Event `json:"events"`
}

// ExportEvents writes all captured events to a timestamped JSON file and
// returns the filename on success.
func ExportEvents(events []Event) (string, error) {
	if len(events) == 0 {
		return "", fmt.Errorf("no events to export")
	}

	filename := fmt.Sprintf("events_%s.json", time.Now().Format("20060102_150405"))

	record := ExportRecord{
		ExportedAt: time.Now().Format(time.RFC3339),
		Events:     events,
	}

	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}

	if err := os.WriteFile(filename, data, 0o644); err != nil {
		return "", fmt.Errorf("write: %w", err)
	}

	return filename, nil
}
