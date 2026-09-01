package app

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/fatih/color"
	"github.com/mr-karan/doggo/pkg/models"
	"github.com/mr-karan/doggo/pkg/resolvers"
)

// captureStdout redirects os.Stdout for the duration of fn and returns
// everything written to it.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	previous := os.Stdout
	os.Stdout = writePipe
	t.Cleanup(func() {
		os.Stdout = previous
	})

	fn()

	if err := writePipe.Close(); err != nil {
		t.Fatalf("stdout close error = %v", err)
	}
	out, err := io.ReadAll(readPipe)
	if err != nil {
		t.Fatalf("stdout read error = %v", err)
	}
	os.Stdout = previous
	return string(out)
}

// captureColorOutput redirects color.Output (used by the terminal renderer)
// for the duration of fn and returns everything written to it.
func captureColorOutput(t *testing.T, fn func()) string {
	t.Helper()

	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	previousColorOutput := color.Output
	previousNoColor := color.NoColor
	color.Output = writePipe
	t.Cleanup(func() {
		color.Output = previousColorOutput
		color.NoColor = previousNoColor
	})

	fn()

	if err := writePipe.Close(); err != nil {
		t.Fatalf("color.Output close error = %v", err)
	}
	out, err := io.ReadAll(readPipe)
	if err != nil {
		t.Fatalf("color.Output read error = %v", err)
	}
	return string(out)
}

func sampleAnswerTrace() resolvers.TraceResult {
	return resolvers.TraceResult{
		SchemaVersion: resolvers.TraceSchemaVersion,
		Query:         resolvers.TraceQuestion{Name: "example.com.", Type: "A", Class: "IN"},
		Status:        resolvers.TraceStatusComplete,
		Verdict:       resolvers.TraceVerdictAnswer,
		Hops: []resolvers.TraceHop{
			{
				Number: 1,
				Zone:   ".",
				Role:   resolvers.TraceRoleRoot,
				Attempts: []resolvers.TraceAttempt{
					{Nameserver: "b.root-servers.net.", IP: "170.247.170.2", Protocol: "udp4", RTTMS: 0, RCode: "",
						Error: &resolvers.TraceError{Code: "timeout", Detail: "i/o timeout"}},
					{Nameserver: "a.root-servers.net.", IP: "198.41.0.4", Protocol: "udp4", RTTMS: 18, RCode: "NOERROR"},
				},
				Delegation: &resolvers.TraceDelegation{
					Child: "com.",
					Nameservers: []resolvers.TraceNameserver{
						{Name: "a.gtld-servers.net.", Addresses: []string{"192.5.6.30"}},
						{Name: "b.gtld-servers.net.", Addresses: []string{"192.33.14.30"}},
						{Name: "c.gtld-servers.net.", Addresses: []string{"192.26.92.30"}},
						{Name: "d.gtld-servers.net.", Addresses: []string{"192.31.80.30"}},
						{Name: "e.gtld-servers.net.", Addresses: []string{"192.12.94.30"}},
					},
				},
				Outcome: resolvers.TraceOutcomeReferral,
			},
			{
				Number: 2,
				Zone:   "com.",
				Role:   resolvers.TraceRoleDelegation,
				Attempts: []resolvers.TraceAttempt{
					{Nameserver: "a.gtld-servers.net.", IP: "192.5.6.30", Protocol: "udp4", RTTMS: 9, RCode: "NOERROR"},
				},
				Delegation: &resolvers.TraceDelegation{
					Child: "example.com.",
					Nameservers: []resolvers.TraceNameserver{
						{Name: "a.iana-servers.net.", Addresses: []string{"199.43.135.53"}},
						{Name: "b.iana-servers.net.", Addresses: []string{"199.43.133.53"}},
					},
				},
				Outcome: resolvers.TraceOutcomeReferral,
			},
			{
				Number: 3,
				Zone:   "example.com.",
				Role:   resolvers.TraceRoleAuthoritative,
				Attempts: []resolvers.TraceAttempt{
					{Nameserver: "a.iana-servers.net.", IP: "199.43.135.53", Protocol: "udp4", RTTMS: 14, RCode: "NOERROR"},
				},
				Answers: []resolvers.TraceRecord{
					{Name: "example.com.", Type: "A", Class: "IN", TTL: 300, Data: "93.184.216.34"},
				},
				Outcome: resolvers.TraceOutcomeAnswer,
			},
		},
		Summary: resolvers.TraceSummary{HopCount: 3, TotalRTTMS: 41},
	}
}

func TestOutputTraceJSONSchema(t *testing.T) {
	app := App{QueryFlags: models.QueryFlags{ShowJSON: true}}
	result := sampleAnswerTrace()

	out := captureStdout(t, func() {
		if err := app.OutputTrace(result); err != nil {
			t.Fatalf("OutputTrace() error = %v", err)
		}
	})

	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\noutput:\n%s", err, out)
	}

	if len(raw) != 2 {
		t.Fatalf("top-level JSON has %d keys, want exactly 2 (schema_version, trace): %v", len(raw), raw)
	}
	if _, ok := raw["schema_version"]; !ok {
		t.Fatalf("top-level JSON missing schema_version: %v", raw)
	}
	traceRaw, ok := raw["trace"].(map[string]interface{})
	if !ok {
		t.Fatalf("top-level JSON missing trace object: %v", raw)
	}

	if _, ok := traceRaw["schema_version"]; ok {
		t.Fatalf("trace object must not duplicate schema_version: %v", traceRaw)
	}

	wantKeys := []string{"query", "status", "verdict", "hops", "summary"}
	for _, key := range wantKeys {
		if _, ok := traceRaw[key]; !ok {
			t.Errorf("trace object missing key %q: %v", key, traceRaw)
		}
	}
	// error is optional (omitempty) and should be absent on a completed trace.
	if _, ok := traceRaw["error"]; ok {
		t.Errorf("trace object should omit error on a completed trace: %v", traceRaw)
	}

	// Re-marshal deterministically twice and compare for stability.
	out2 := captureStdout(t, func() {
		if err := app.OutputTrace(result); err != nil {
			t.Fatalf("OutputTrace() error = %v", err)
		}
	})
	if out != out2 {
		t.Errorf("OutputTrace() JSON output is not stable across calls:\nfirst:\n%s\nsecond:\n%s", out, out2)
	}

	if strings.Contains(out, "\x1b[") {
		t.Errorf("JSON output must never contain ANSI escape sequences:\n%s", out)
	}

	if !strings.HasSuffix(out, "\n") {
		t.Errorf("JSON output should end with a newline")
	}
}

func TestOutputTraceJSONErrorField(t *testing.T) {
	app := App{QueryFlags: models.QueryFlags{ShowJSON: true}}
	result := resolvers.TraceResult{
		SchemaVersion: resolvers.TraceSchemaVersion,
		Query:         resolvers.TraceQuestion{Name: "example.com.", Type: "A", Class: "IN"},
		Status:        resolvers.TraceStatusPartial,
		Verdict:       resolvers.TraceVerdictError,
		Hops: []resolvers.TraceHop{
			{
				Number:  1,
				Zone:    ".",
				Role:    resolvers.TraceRoleRoot,
				Outcome: resolvers.TraceOutcomeError,
			},
		},
		Summary: resolvers.TraceSummary{HopCount: 1},
		Error:   &resolvers.TraceError{Code: "timeout", Detail: "i/o timeout"},
	}

	out := captureStdout(t, func() {
		if err := app.OutputTrace(result); err != nil {
			t.Fatalf("OutputTrace() error = %v", err)
		}
	})

	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\noutput:\n%s", err, out)
	}
	traceRaw := raw["trace"].(map[string]interface{})
	errRaw, ok := traceRaw["error"].(map[string]interface{})
	if !ok {
		t.Fatalf("trace object missing structured error: %v", traceRaw)
	}
	if errRaw["code"] != "timeout" {
		t.Errorf("trace error code = %v, want %q", errRaw["code"], "timeout")
	}
	if errRaw["detail"] != "i/o timeout" {
		t.Errorf("trace error detail = %v, want %q", errRaw["detail"], "i/o timeout")
	}
	if traceRaw["status"] != string(resolvers.TraceStatusPartial) {
		t.Errorf("trace status = %v, want %q", traceRaw["status"], resolvers.TraceStatusPartial)
	}
}

func TestOutputTraceShort(t *testing.T) {
	app := App{QueryFlags: models.QueryFlags{ShortOutput: true}}
	result := sampleAnswerTrace()

	out := captureStdout(t, func() {
		if err := app.OutputTrace(result); err != nil {
			t.Fatalf("OutputTrace() error = %v", err)
		}
	})

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("short output has %d lines, want 4 (3 hops + 1 answer):\n%s", len(lines), out)
	}

	for i, zone := range []string{".", "com.", "example.com."} {
		fields := strings.Split(lines[i], "\t")
		if len(fields) < 2 {
			t.Fatalf("short output line %d = %q, want tab-separated fields", i, lines[i])
		}
		if fields[0] != zone {
			t.Errorf("short output line %d zone = %q, want %q", i, fields[0], zone)
		}
	}

	if lines[3] != "93.184.216.34" {
		t.Errorf("short output final line = %q, want final answer data %q", lines[3], "93.184.216.34")
	}

	if strings.Contains(out, "\x1b[") {
		t.Errorf("short output must never contain ANSI escape sequences:\n%s", out)
	}
}

func TestOutputTraceShortSkipsErrorHops(t *testing.T) {
	app := App{QueryFlags: models.QueryFlags{ShortOutput: true}}
	result := resolvers.TraceResult{
		Hops: []resolvers.TraceHop{
			{Number: 1, Zone: ".", Outcome: resolvers.TraceOutcomeError},
		},
		Status: resolvers.TraceStatusFailed,
	}

	out := captureStdout(t, func() {
		if err := app.OutputTrace(result); err != nil {
			t.Fatalf("OutputTrace() error = %v", err)
		}
	})

	if out != "" {
		t.Errorf("short output for a failed hop with no successful attempts = %q, want empty", out)
	}
}

func TestOutputTraceTerminalRendersHopDetails(t *testing.T) {
	app := App{QueryFlags: models.QueryFlags{Color: false}}
	result := sampleAnswerTrace()

	out := captureColorOutput(t, func() {
		if err := app.OutputTrace(result); err != nil {
			t.Fatalf("OutputTrace() error = %v", err)
		}
	})

	wantSubstrings := []string{
		"TRACE  example.com.  A  IN",
		".",
		"root",
		"b.root-servers.net.",
		"FAILED",
		"a.root-servers.net.",
		"198.41.0.4",
		"18ms",
		"NOERROR",
		"delegates com. to a.gtld-servers.net.",
		"+ 1 more",
		"com.",
		"delegation",
		"a.gtld-servers.net.",
		"delegates example.com. to a.iana-servers.net. (199.43.135.53), b.iana-servers.net. (199.43.133.53)",
		"example.com.",
		"authoritative",
		"a.iana-servers.net.",
		"199.43.135.53",
		"14ms",
		"ANSWER",
		"93.184.216.34",
		"3 hops",
		"41ms total",
		"answer from a.iana-servers.net.",
	}

	position := 0
	for _, want := range wantSubstrings {
		next := strings.Index(out[position:], want)
		if next < 0 {
			t.Fatalf("terminal trace output missing %q in expected order after byte %d:\n%s", want, position, out)
		}
		position += next + len(want)
	}

	if strings.Contains(out, "\x1b[") {
		t.Errorf("terminal output with Color=false must never contain ANSI escape sequences:\n%s", out)
	}
}

func TestOutputTraceTerminalHonorsColorTrue(t *testing.T) {
	app := App{QueryFlags: models.QueryFlags{Color: true}}
	result := sampleAnswerTrace()

	out := captureColorOutput(t, func() {
		if err := app.OutputTrace(result); err != nil {
			t.Fatalf("OutputTrace() error = %v", err)
		}
	})

	// Regardless of color, the ANSWER data must still be textually present so
	// the meaning never depends solely on color.
	if !strings.Contains(stripANSI(out), "93.184.216.34") {
		t.Errorf("terminal output missing answer data even after stripping ANSI:\n%s", out)
	}
}

func TestOutputTraceTerminalNegativeVerdicts(t *testing.T) {
	tests := []struct {
		name    string
		outcome resolvers.TraceOutcome
		verdict resolvers.TraceVerdict
		want    string
	}{
		{
			name:    "nxdomain",
			outcome: resolvers.TraceOutcomeNXDOMAIN,
			verdict: resolvers.TraceVerdictNXDOMAIN,
			want:    "NXDOMAIN",
		},
		{
			name:    "nodata",
			outcome: resolvers.TraceOutcomeNODATA,
			verdict: resolvers.TraceVerdictNODATA,
			want:    "NODATA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := App{QueryFlags: models.QueryFlags{Color: false}}
			result := resolvers.TraceResult{
				Query:   resolvers.TraceQuestion{Name: "nx.example.com.", Type: "A", Class: "IN"},
				Status:  resolvers.TraceStatusComplete,
				Verdict: tt.verdict,
				Hops: []resolvers.TraceHop{
					{
						Number: 1,
						Zone:   "example.com.",
						Role:   resolvers.TraceRoleAuthoritative,
						Attempts: []resolvers.TraceAttempt{
							{Nameserver: "a.iana-servers.net.", IP: "199.43.135.53", Protocol: "udp4", RTTMS: 5, RCode: "NOERROR"},
						},
						Authorities: []resolvers.TraceRecord{
							{Name: "example.com.", Type: "SOA", Class: "IN", TTL: 3600, Data: "a.iana-servers.net. noc.dns.icann.org. 1 1 1 1 1"},
						},
						Outcome: tt.outcome,
					},
				},
				Summary: resolvers.TraceSummary{HopCount: 1, TotalRTTMS: 5},
			}

			out := captureColorOutput(t, func() {
				if err := app.OutputTrace(result); err != nil {
					t.Fatalf("OutputTrace() error = %v", err)
				}
			})

			if !strings.Contains(out, tt.want) {
				t.Errorf("terminal output missing %q for outcome %s:\n%s", tt.want, tt.outcome, out)
			}
			if strings.Contains(out, "\x1b[") {
				t.Errorf("terminal output with Color=false must never contain ANSI escape sequences:\n%s", out)
			}
		})
	}
}

func TestOutputTraceTerminalPartialError(t *testing.T) {
	app := App{QueryFlags: models.QueryFlags{Color: false}}
	result := resolvers.TraceResult{
		Query:   resolvers.TraceQuestion{Name: "example.com.", Type: "A", Class: "IN"},
		Status:  resolvers.TraceStatusPartial,
		Verdict: resolvers.TraceVerdictError,
		Hops: []resolvers.TraceHop{
			{
				Number: 1,
				Zone:   ".",
				Role:   resolvers.TraceRoleRoot,
				Attempts: []resolvers.TraceAttempt{
					{Nameserver: "a.root-servers.net.", IP: "198.41.0.4", Protocol: "udp4",
						Error: &resolvers.TraceError{Code: "timeout", Detail: "i/o timeout"}},
				},
				Outcome: resolvers.TraceOutcomeError,
			},
		},
		Summary: resolvers.TraceSummary{HopCount: 1},
		Error:   &resolvers.TraceError{Code: "no_nameserver_address", Detail: "no usable nameserver address for ."},
	}

	out := captureColorOutput(t, func() {
		if err := app.OutputTrace(result); err != nil {
			t.Fatalf("OutputTrace() error = %v", err)
		}
	})

	for _, want := range []string{"FAILED", "timeout", "partial", "no_nameserver_address"} {
		if !strings.Contains(out, want) {
			t.Errorf("partial terminal output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Errorf("terminal output with Color=false must never contain ANSI escape sequences:\n%s", out)
	}
}

func TestOutputTraceNeverPanicsOnEmptyResult(t *testing.T) {
	for _, flags := range []models.QueryFlags{
		{ShowJSON: true},
		{ShortOutput: true},
		{Color: false},
	} {
		app := App{QueryFlags: flags}
		var callErr error
		captureColorOutput(t, func() {
			captureStdout(t, func() {
				callErr = app.OutputTrace(resolvers.TraceResult{})
			})
		})
		if callErr != nil {
			t.Errorf("OutputTrace() with empty result and flags %+v returned error = %v", flags, callErr)
		}
	}
}

// stripANSI removes SGR escape sequences so assertions about textual meaning
// can run regardless of whether color was enabled.
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && s[j] != 'm' {
				j++
			}
			i = j
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
