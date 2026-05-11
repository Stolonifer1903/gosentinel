package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Session represents an active logging session that records all terminal output.
type Session struct {
	file *os.File
	out  io.Writer
}

// StartSession initializes a new logging session. It creates the logs/ directory
// if it doesn't exist, opens a new log file with the current timestamp, writes
// the command line arguments to it, and returns a Session.
// If an error occurs, it returns nil and the error.
func StartSession() (*Session, error) {
	logDir := "logs"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create logs directory: %w", err)
	}

	timestamp := time.Now().Format("2006-01-02_150405")
	logPath := filepath.Join(logDir, fmt.Sprintf("scan_%s.log", timestamp))

	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	// Write the command line to the top of the file
	var quotedArgs []string
	for _, arg := range os.Args {
		if strings.ContainsAny(arg, " ;\"'") {
			quotedArgs = append(quotedArgs, fmt.Sprintf("%q", arg))
		} else {
			quotedArgs = append(quotedArgs, arg)
		}
	}
	cmdLine := strings.Join(quotedArgs, " ")
	header := fmt.Sprintf("=== GoSentinel Scan Session ===\nTime: %s\nCommand: %s\n===============================\n\n", time.Now().Format(time.RFC3339), cmdLine)
	if _, err := file.WriteString(header); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to write log header: %w", err)
	}

	// MultiWriter duplicates output to both standard output and the file
	out := io.MultiWriter(os.Stdout, file)

	return &Session{
		file: file,
		out:  out,
	}, nil
}

// Writer returns the io.Writer that should be used for printing to the terminal
// and logging to the file simultaneously.
func (s *Session) Writer() io.Writer {
	return s.out
}

// Close closes the underlying log file.
func (s *Session) Close() error {
	if s.file != nil {
		footer := fmt.Sprintf("\n===============================\nSession ended at: %s\n", time.Now().Format(time.RFC3339))
		s.file.WriteString(footer)
		return s.file.Close()
	}
	return nil
}
