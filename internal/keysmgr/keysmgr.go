// Copyright (c) 2026 FLINTEK LLC
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the project root for license information.

// Package keysmgr provides an interactive bubbletea TUI for managing API keys
// stored in a .env file on disk.
package keysmgr

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// KeyDef describes a single configurable key shown in the menu.
type KeyDef struct {
	EnvKey string
	Label  string
	Desc   string
}

// AllKeys is the ordered list of keys Observer supports.
var AllKeys = []KeyDef{
	{"SHODAN_API_KEY", "Shodan", "https://account.shodan.io/register"},
	{"VIRUSTOTAL_API_KEY", "VirusTotal", "https://www.virustotal.com/gui/join-us"},
	{"ABUSEIPDB_API_KEY", "AbuseIPDB", "https://www.abuseipdb.com/register"},
	{"OTX_API_KEY", "AlienVault OTX", "https://otx.alienvault.com/"},
	{"IPINFO_TOKEN", "ipinfo.io token", "https://ipinfo.io/signup"},
	{"OBSERVER_API_KEY", "Observer server key", "(optional — protects the web server API)"},
}

// ─── State ───────────────────────────────────────────────────────────────────

type viewState int

const (
	stateList viewState = iota
	stateEdit
	stateSaved
)

// Model is the bubbletea model for the key manager.
type Model struct {
	keys    []KeyDef
	values  map[string]string // current in-memory values
	cursor  int
	state   viewState
	input   textinput.Model
	envPath string
	saveErr string
	width   int
}

// New creates a Model, loading existing values from envPath (if it exists).
func New(envPath string) (Model, error) {
	if envPath == "" {
		envPath = ".env"
	}
	abs, err := filepath.Abs(envPath)
	if err != nil {
		return Model{}, err
	}

	values := loadEnv(abs)

	ti := textinput.New()
	ti.CharLimit = 256
	ti.Width = 52

	return Model{
		keys:    AllKeys,
		values:  values,
		envPath: abs,
		input:   ti,
	}, nil
}

// ─── Init / Update / View ────────────────────────────────────────────────────

func (m Model) Init() tea.Cmd { return nil }

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil

	case tea.KeyMsg:
		switch m.state {

		case stateList:
			switch msg.String() {
			case "q", "ctrl+c":
				return m, tea.Quit
			case "up", "k":
				if m.cursor > 0 {
					m.cursor--
				}
			case "down", "j":
				if m.cursor < len(m.keys)-1 {
					m.cursor++
				}
			case "enter", " ":
				m.state = stateEdit
				m.input.SetValue(m.values[m.keys[m.cursor].EnvKey])
				m.input.Focus()
				m.input.CursorEnd()
				return m, textinput.Blink
			case "d", "delete":
				// Clear the current key.
				delete(m.values, m.keys[m.cursor].EnvKey)
				m.saveErr = ""
			case "ctrl+s", "s":
				if err := saveEnv(m.envPath, m.keys, m.values); err != nil {
					m.saveErr = "save failed: " + err.Error()
				} else {
					m.state = stateSaved
				}
				return m, nil
			}

		case stateEdit:
			switch msg.String() {
			case "ctrl+c":
				return m, tea.Quit
			case "esc":
				m.state = stateList
				m.input.Blur()
			case "enter":
				val := strings.TrimSpace(m.input.Value())
				if val == "" {
					delete(m.values, m.keys[m.cursor].EnvKey)
				} else {
					m.values[m.keys[m.cursor].EnvKey] = val
				}
				m.state = stateList
				m.input.Blur()
			default:
				var cmd tea.Cmd
				m.input, cmd = m.input.Update(msg)
				return m, cmd
			}

		case stateSaved:
			return m, tea.Quit
		}
	}
	return m, nil
}

// ─── Styles ──────────────────────────────────────────────────────────────────

var (
	stylePurple   = lipgloss.NewStyle().Foreground(lipgloss.Color("#A78BFA")).Bold(true)
	styleBlue     = lipgloss.NewStyle().Foreground(lipgloss.Color("#60A5FA"))
	styleGreen    = lipgloss.NewStyle().Foreground(lipgloss.Color("#4ADE80"))
	styleMuted    = lipgloss.NewStyle().Foreground(lipgloss.Color("#6B7280"))
	styleDim      = lipgloss.NewStyle().Foreground(lipgloss.Color("#94A3B8"))
	styleYellow   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FBBF24"))
	styleRed      = lipgloss.NewStyle().Foreground(lipgloss.Color("#F87171"))
	styleBold     = lipgloss.NewStyle().Bold(true)
	styleSelected = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#1E1B4B")).
			Background(lipgloss.Color("#A78BFA")).
			Bold(true).
			PaddingLeft(1).PaddingRight(1)
	styleBorder = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#4C1D95")).
			Padding(1, 2)
)

func (m Model) View() string {
	var sb strings.Builder

	title := stylePurple.Render("  Observer — API Key Manager  ")
	sb.WriteString("\n" + title + "\n")
	sb.WriteString(styleMuted.Render("  Configure enrichment source keys · saved to "+m.envPath) + "\n\n")

	switch m.state {

	case stateList:
		sb.WriteString(styleBlue.Render("  ↑/↓  navigate    Enter  edit    d  clear key    Ctrl+S  save & exit    q  quit\n\n"))

		for i, k := range m.keys {
			val := m.values[k.EnvKey]
			maskedVal := maskKey(val)

			var statusIcon string
			if val != "" {
				statusIcon = styleGreen.Render("✓")
			} else {
				statusIcon = styleMuted.Render("·")
			}

			label := fmt.Sprintf("%-20s", k.Label)
			if i == m.cursor {
				row := fmt.Sprintf("  %s  %s  %s", statusIcon, label, maskedVal)
				sb.WriteString(styleSelected.Render(row) + "\n")
			} else {
				row := fmt.Sprintf("  %s  %s  %s", statusIcon, styleBold.Render(label), styleDim.Render(maskedVal))
				sb.WriteString("  " + row + "\n")
			}

			if i == m.cursor {
				sb.WriteString(styleMuted.Render("         Signup: "+k.Desc) + "\n")
			}
		}

		sb.WriteString("\n")
		if m.saveErr != "" {
			sb.WriteString(styleRed.Render("  ⚠ "+m.saveErr) + "\n")
		} else {
			sb.WriteString(styleMuted.Render("  Unsaved changes. Press Ctrl+S to save.") + "\n")
		}

	case stateEdit:
		k := m.keys[m.cursor]
		sb.WriteString(styleYellow.Render("  Editing: "+k.Label) + "\n")
		sb.WriteString(styleMuted.Render("  "+k.Desc) + "\n\n")
		sb.WriteString("  " + m.input.View() + "\n\n")
		sb.WriteString(styleMuted.Render("  Enter  confirm    Esc  cancel") + "\n")

	case stateSaved:
		sb.WriteString(styleGreen.Render("  ✓ Keys saved to "+m.envPath) + "\n")
		sb.WriteString(styleMuted.Render("  Run `observe config` to verify.\n"))
	}

	sb.WriteString("\n")
	return sb.String()
}

// maskKey shows the first 4 chars and masks the rest, or "[not configured]" if empty.
func maskKey(val string) string {
	if val == "" {
		return "[not configured]"
	}
	if len(val) <= 4 {
		return strings.Repeat("*", len(val))
	}
	return val[:4] + strings.Repeat("*", min(len(val)-4, 20)) + "  ✓"
}

// ─── .env file I/O ───────────────────────────────────────────────────────────

// loadEnv reads key=value pairs from a .env file.
// Lines starting with # and blank lines are ignored.
// Returns an empty map if the file does not exist.
func loadEnv(path string) map[string]string {
	vals := make(map[string]string)
	f, err := os.Open(path)
	if err != nil {
		return vals
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			vals[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return vals
}

// saveEnv writes all managed keys to the .env file, preserving comments and
// any non-Observer keys that were already there.
func saveEnv(path string, keys []KeyDef, values map[string]string) error {
	// Build a set of known keys for fast lookup.
	knownKeys := make(map[string]bool, len(keys))
	for _, k := range keys {
		knownKeys[k.EnvKey] = true
	}

	// Read existing file to preserve comments and unknown keys.
	var existingLines []string
	existingKeys := make(map[string]bool)

	if f, err := os.Open(path); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			existingLines = append(existingLines, scanner.Text())
			line := strings.TrimSpace(scanner.Text())
			if !strings.HasPrefix(line, "#") && strings.Contains(line, "=") {
				parts := strings.SplitN(line, "=", 2)
				existingKeys[strings.TrimSpace(parts[0])] = true
			}
		}
		f.Close()
	}

	// Build the new file content.
	var out strings.Builder

	// Pass 1: rewrite existing lines, updating known key values in place.
	for _, line := range existingLines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			out.WriteString(line + "\n")
			continue
		}
		parts := strings.SplitN(trimmed, "=", 2)
		if len(parts) != 2 {
			out.WriteString(line + "\n")
			continue
		}
		key := strings.TrimSpace(parts[0])
		if knownKeys[key] {
			// Write the updated value (or skip entirely if cleared).
			val := values[key]
			out.WriteString(key + "=" + val + "\n")
		} else {
			// Preserve unknown keys unchanged.
			out.WriteString(line + "\n")
		}
	}

	// Pass 2: append any new known keys that weren't in the file yet.
	for _, k := range keys {
		if !existingKeys[k.EnvKey] {
			val := values[k.EnvKey]
			out.WriteString(k.EnvKey + "=" + val + "\n")
		}
	}

	return os.WriteFile(path, []byte(out.String()), 0600)
}

// Run launches the interactive TUI and blocks until the user exits.
func Run(envPath string) error {
	m, err := New(envPath)
	if err != nil {
		return err
	}
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err = p.Run()
	return err
}
