package ux

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
)

// Colors for output
var (
	Green  = color.New(color.FgGreen).SprintFunc()
	Red    = color.New(color.FgRed).SprintFunc()
	Yellow = color.New(color.FgYellow).SprintFunc()
	Blue   = color.New(color.FgBlue).SprintFunc()
	Cyan   = color.New(color.FgCyan).SprintFunc()
	Bold   = color.New(color.Bold).SprintFunc()
)

// Success prints a success message
func Success(msg string) {
	fmt.Printf("%s %s\n", Green("✅"), msg)
}

// Error prints an error message
func Error(msg string) {
	fmt.Printf("%s %s\n", Red("❌"), msg)
}

// Warning prints a warning message
func Warning(msg string) {
	fmt.Printf("%s %s\n", Yellow("⚠️"), msg)
}

// Info prints an info message
func Info(msg string) {
	fmt.Printf("%s %s\n", Blue("ℹ️"), msg)
}

// PrintHeader prints a header
func PrintHeader(title string) {
	fmt.Printf("\n%s\n", Bold(title))
	fmt.Println(strings.Repeat("=", len(title)))
}

// PrintTable prints a simple table
func PrintTable(headers []string, rows [][]string) {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	for i, h := range headers {
		fmt.Printf("%-*s  ", widths[i], h)
	}
	fmt.Println()

	for i := range headers {
		fmt.Printf("%s  ", strings.Repeat("-", widths[i]))
	}
	fmt.Println()

	for _, row := range rows {
		for i, cell := range row {
			fmt.Printf("%-*s  ", widths[i], cell)
		}
		fmt.Println()
	}
}

// ProgressBar represents a simple progress bar
type ProgressBar struct {
	Total   int
	Current int
	Width   int
	Prefix  string
}

// NewProgressBar creates a new progress bar
func NewProgressBar(total int, prefix string) *ProgressBar {
	return &ProgressBar{
		Total:   total,
		Current: 0,
		Width:   40,
		Prefix:  prefix,
	}
}

// Add increments the progress
func (pb *ProgressBar) Add(n int) {
	pb.Current += n
	if pb.Current > pb.Total {
		pb.Current = pb.Total
	}
	pb.Render()
}

// Set sets the current progress
func (pb *ProgressBar) Set(n int) {
	pb.Current = n
	if pb.Current > pb.Total {
		pb.Current = pb.Total
	}
	pb.Render()
}

// Render renders the progress bar
func (pb *ProgressBar) Render() {
	percent := float64(pb.Current) / float64(pb.Total) * 100
	filled := int(float64(pb.Width) * float64(pb.Current) / float64(pb.Total))
	empty := pb.Width - filled

	bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)
	fmt.Printf("\r%s [%s] %.1f%%", pb.Prefix, bar, percent)
	if pb.Current >= pb.Total {
		fmt.Println()
	}
}

// Complete marks the progress bar as complete
func (pb *ProgressBar) Complete() {
	pb.Current = pb.Total
	pb.Render()
}

// Spinner represents a simple spinner
type Spinner struct {
	Chars  []string
	Index  int
	Prefix string
	Stop   chan bool
}

// NewSpinner creates a new spinner
func NewSpinner(prefix string) *Spinner {
	return &Spinner{
		Chars:  []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		Index:  0,
		Prefix: prefix,
		Stop:   make(chan bool),
	}
}

// Start starts the spinner
func (s *Spinner) Start() {
	go func() {
		for {
			select {
			case <-s.Stop:
				fmt.Printf("\r%s Done!     \n", s.Prefix)
				return
			default:
				fmt.Printf("\r%s %s", s.Prefix, s.Chars[s.Index])
				s.Index = (s.Index + 1) % len(s.Chars)
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()
}

// StopSpinner stops the spinner
func (s *Spinner) StopSpinner() {
	s.Stop <- true
}
