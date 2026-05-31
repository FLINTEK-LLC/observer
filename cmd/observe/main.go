// Copyright (c) 2026 FLINTEK LLC
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the project root for license information.

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/ctrlaltdean/observer/config"
	"github.com/ctrlaltdean/observer/internal/keysmgr"
	"github.com/ctrlaltdean/observer/internal/model"
	"github.com/ctrlaltdean/observer/internal/render"
	"github.com/ctrlaltdean/observer/internal/runner"
)

// Version is set at build time via -ldflags "-X main.Version=...".
// For binaries installed with go install, resolveVersion() reads the embedded module info instead.
var Version = "dev"

func resolveVersion() string {
	if Version != "dev" {
		return Version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return Version
}

// ─── Bubbletea spinner model ──────────────────────────────────────────────────

type resultMsg struct {
	result *model.EnrichmentResult
	err    error
}

type spinnerModel struct {
	sp      spinner.Model
	label   string
	done    bool
	result  *model.EnrichmentResult
	err     error
	program *tea.Program
}

func newSpinnerModel(label string) spinnerModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#A78BFA"))
	return spinnerModel{sp: s, label: label}
}

func (m spinnerModel) Init() tea.Cmd { return m.sp.Tick }

func (m spinnerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case resultMsg:
		m.done = true
		m.result = msg.result
		m.err = msg.err
		return m, tea.Quit
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.sp, cmd = m.sp.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m spinnerModel) View() string {
	if m.done {
		return ""
	}
	return m.sp.View() + " " + m.label + "\n"
}

// runWithSpinner runs the enrichment with a bubbletea spinner if stdout is a TTY.
func runWithSpinner(ctx context.Context, observable string, cfg *config.Config, sources []string) (*model.EnrichmentResult, error) {
	isTTY := term.IsTerminal(int(os.Stdout.Fd()))

	if !isTTY {
		return runner.RunWithOptions(ctx, observable, cfg, nil, sources)
	}

	model := newSpinnerModel(fmt.Sprintf("Enriching %s ...", observable))
	p := tea.NewProgram(model)
	model.program = p

	go func() {
		result, err := runner.RunWithOptions(ctx, observable, cfg, nil, sources)
		p.Send(resultMsg{result: result, err: err})
	}()

	final, err := p.Run()
	if err != nil {
		return nil, fmt.Errorf("spinner error: %w", err)
	}
	m := final.(spinnerModel)
	return m.result, m.err
}

// ─── Root command ─────────────────────────────────────────────────────────────

func main() {
	var (
		cfgFile string
		format  string
		sources string
	)

	cfg, _ := config.Load("")

	root := &cobra.Command{
		Use:   "observe <observable>",
		Short: "Enrich a network observable (IP, domain, URL, or hash) across multiple threat intel sources",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}

			// Reload config with any explicitly specified file.
			if cfgFile != "" {
				var err error
				cfg, err = config.Load(cfgFile)
				if err != nil {
					return err
				}
			}

			observable := args[0]
			var srcList []string
			if sources != "" {
				parts := strings.Split(sources, ",")
				srcList = make([]string, 0, len(parts))
				for _, s := range parts {
					srcList = append(srcList, strings.TrimSpace(s))
				}
			}

			ctx := context.Background()
			result, err := runWithSpinner(ctx, observable, cfg, srcList)
			if err != nil {
				return fmt.Errorf("enrichment failed: %w", err)
			}

			return render.Render(result, render.Format(format), os.Stdout)
		},
	}

	root.PersistentFlags().StringVar(&cfgFile, "config", "", "path to .env config file")
	root.PersistentFlags().StringVar(&format, "format", "table", "output format: table, json, markdown, csv")
	root.PersistentFlags().StringVar(&sources, "sources", "", "comma-separated list of sources to run (e.g. vt,shodan)")

	// ─── version ──────────────────────────────────────────────────────────
	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("observe version %s\n", resolveVersion())
		},
	})

	// ─── update ───────────────────────────────────────────────────────────
	root.AddCommand(&cobra.Command{
		Use:   "update",
		Short: "Check for a newer version and update if available",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdate()
		},
	})

	// ─── keys ─────────────────────────────────────────────────────────────
	root.AddCommand(&cobra.Command{
		Use:   "keys",
		Short: "Interactively configure API keys and save them to .env",
		Long: `Open an interactive menu to view, add, and update API keys.
Changes are saved to the .env file in the current directory (or the path
specified by --config).

Navigation: ↑/↓ or j/k  |  Enter: edit  |  d: clear  |  Ctrl+S: save & exit  |  q: quit`,
		RunE: func(cmd *cobra.Command, args []string) error {
			envPath := cfgFile
			if envPath == "" {
				envPath = ".env"
			}
			return keysmgr.Run(envPath)
		},
	})

	// ─── config ───────────────────────────────────────────────────────────
	root.AddCommand(&cobra.Command{
		Use:   "config",
		Short: "Validate config and show which sources are active",
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfgFile != "" {
				var err error
				cfg, err = config.Load(cfgFile)
				if err != nil {
					return err
				}
			}

			active := cfg.ActiveSources()

			labelStyle := lipgloss.NewStyle().Width(16)
			greenStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#4ADE80"))
			redStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#F87171"))

			anyActive := false
			isTTY := term.IsTerminal(int(os.Stdout.Fd()))

			fmt.Println("\nSource Configuration")
			fmt.Println(strings.Repeat("─", 40))

			for _, name := range []string{"shodan", "virustotal", "abuseipdb", "whois", "otx", "ipinfo"} {
				isActive := active[name]
				if isActive {
					anyActive = true
				}
				var statusStr string
				if isTTY {
					if isActive {
						statusStr = greenStyle.Render("✅ configured")
					} else {
						statusStr = redStyle.Render("❌ no key")
					}
				} else {
					if isActive {
						statusStr = "[ok]"
					} else {
						statusStr = "[no key]"
					}
				}
				if isTTY {
					fmt.Printf("  %s %s\n", labelStyle.Render(name), statusStr)
				} else {
					fmt.Printf("  %-16s %s\n", name, statusStr)
				}
			}
			fmt.Println()

			if !anyActive {
				fmt.Fprintln(os.Stderr, "ERROR: no sources configured. Set at least one API key in .env or environment.")
				os.Exit(1)
			}
			return nil
		},
	})

	// ─── bulk ─────────────────────────────────────────────────────────────
	var bulkStdin bool
	bulkCmd := &cobra.Command{
		Use:   "bulk [file]",
		Short: "Enrich multiple observables from a file (one per line) or stdin",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfgFile != "" {
				var err error
				cfg, err = config.Load(cfgFile)
				if err != nil {
					return err
				}
			}

			var scanner *bufio.Scanner
			if bulkStdin {
				scanner = bufio.NewScanner(os.Stdin)
			} else if len(args) == 1 {
				f, err := os.Open(args[0])
				if err != nil {
					return fmt.Errorf("open file: %w", err)
				}
				defer f.Close()
				scanner = bufio.NewScanner(f)
			} else {
				return fmt.Errorf("provide a file path or use --stdin")
			}

			var observables []string
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				observables = append(observables, line)
			}
			if err := scanner.Err(); err != nil {
				return fmt.Errorf("read error: %w", err)
			}

			return runBulk(observables, cfg, format, sources)
		},
	}
	bulkCmd.Flags().BoolVar(&bulkStdin, "stdin", false, "read observables from stdin")
	root.AddCommand(bulkCmd)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// runUpdate checks GitHub for a newer release and updates via go install if one is found.
func runUpdate() error {
	fmt.Print("Checking for updates... ")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/repos/ctrlaltdean/observer/releases/latest", nil)
	if err != nil {
		return fmt.Errorf("could not build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("could not reach GitHub: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode)
	}

	var release struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return fmt.Errorf("could not parse response: %w", err)
	}

	ver := resolveVersion()
	fmt.Printf("current: %s  latest: %s\n", ver, release.TagName)

	if ver == "dev" {
		fmt.Printf("Running a dev build — skipping auto-update.\n")
		fmt.Printf("Latest release: %s\n  %s\n", release.TagName, release.HTMLURL)
		return nil
	}

	// Normalize both to "vX.Y.Z" for comparison.
	current := "v" + strings.TrimPrefix(ver, "v")
	latest := "v" + strings.TrimPrefix(release.TagName, "v")
	if current == latest {
		fmt.Println("Already up to date.")
		return nil
	}

	// Different version — attempt go install.
	fmt.Printf("Updating to %s...\n", release.TagName)
	goBin, err := exec.LookPath("go")
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n'go' not found in PATH — download the binary directly:\n  %s\n", release.HTMLURL)
		return nil
	}
	cmd := exec.CommandContext(ctx, goBin, "install",
		"github.com/ctrlaltdean/observer/cmd/observe@latest")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "\ngo install failed — download the binary directly:\n  %s\n", release.HTMLURL)
		return nil
	}
	fmt.Println("Update complete. Restart observe to use the new version.")
	return nil
}

// runBulk processes multiple observables with bounded concurrency.
func runBulk(observables []string, cfg *config.Config, format string, sourcesStr string) error {
	var srcList []string
	if sourcesStr != "" {
		parts := strings.Split(sourcesStr, ",")
		srcList = make([]string, 0, len(parts))
		for _, s := range parts {
			srcList = append(srcList, strings.TrimSpace(s))
		}
	}

	sem := make(chan struct{}, cfg.BulkConcurrency)

	var (
		mu      sync.Mutex
		results []*model.EnrichmentResult
		errs    []string
		wg      sync.WaitGroup
	)

	isJSON := render.Format(format) == render.FormatJSON

	for _, obs := range observables {
		obs := obs
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.EnricherTimeoutSeconds+5)*time.Second)
			defer cancel()

			result, err := runner.RunWithOptions(ctx, obs, cfg, nil, srcList)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", obs, err))
				return
			}
			results = append(results, result)

			if !isJSON {
				// Print immediately for non-JSON formats.
				if rerr := render.Render(result, render.Format(format), os.Stdout); rerr != nil {
					fmt.Fprintf(os.Stderr, "  render error for %s: %v\n", result.Observable, rerr)
				}
				fmt.Println()
			}
		}()
	}
	wg.Wait()

	if isJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			fmt.Fprintf(os.Stderr, "error encoding JSON results: %v\n", err)
		}
	}

	fmt.Printf("\nSummary: %d processed, %d errors\n", len(results), len(errs))
	for _, e := range errs {
		fmt.Fprintf(os.Stderr, "  error: %s\n", e)
	}
	return nil
}
