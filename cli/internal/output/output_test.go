package output

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"
)

func withoutColor(t *testing.T) {
	t.Helper()
	previous := color.NoColor
	color.NoColor = true
	t.Cleanup(func() { color.NoColor = previous })
}

func capture(t *testing.T, stream **os.File, fn func()) string {
	t.Helper()
	original := *stream
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	*stream = writer
	previousColorOutput := color.Output
	previousColorError := color.Error
	if stream == &os.Stdout {
		color.Output = writer
	}
	if stream == &os.Stderr {
		color.Error = writer
	}
	fn()
	writer.Close()
	*stream = original
	color.Output = previousColorOutput
	color.Error = previousColorError
	data, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestMessageAndLayoutOutput(t *testing.T) {
	withoutColor(t)
	stdout := capture(t, &os.Stdout, func() {
		Success("saved %d", 2)
		Info("details")
		Warn("careful")
		Header("Title")
		Field("Name", "value")
		FieldHighlight("URL", "https://example.test")
		Divider()
		SecretBox("top secret")
	})
	for _, expected := range []string{
		"Success: saved 2", "Info: details", "Warning: careful", "Title",
		"Name:", "value", "URL:", "https://example.test", "top secret",
	} {
		if !strings.Contains(stdout, expected) {
			t.Errorf("stdout missing %q:\n%s", expected, stdout)
		}
	}
	stderr := capture(t, &os.Stderr, func() { Error("failed: %s", "reason") })
	if !strings.Contains(stderr, "Error: failed: reason") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestBannerAndTable(t *testing.T) {
	withoutColor(t)
	banner := capture(t, &os.Stdout, Banner)
	if !strings.Contains(banner, "██████") || !strings.Contains(banner, "Secure secret sharing") {
		t.Fatalf("unexpected banner:\n%s", banner)
	}
	var buffer bytes.Buffer
	table := NewTable(&buffer, []string{"NAME", "VALUE"})
	table.Append([]string{"alpha", "one"})
	table.Render()
	text := buffer.String()
	for _, expected := range []string{"NAME", "VALUE", "alpha", "one"} {
		if !strings.Contains(text, expected) {
			t.Errorf("table missing %q:\n%s", expected, text)
		}
	}
}

func TestFormattingHelpers(t *testing.T) {
	withoutColor(t)
	when := time.Date(2026, 2, 3, 4, 5, 6, 0, time.Local)
	if FormatTime(when) != "2026-02-03 04:05:06" {
		t.Fatalf("FormatTime = %q", FormatTime(when))
	}
	if FormatDuration(time.Now().Add(-time.Second)) != "expired" {
		t.Fatalf("past duration was not expired")
	}
	durations := []struct {
		future   time.Duration
		contains string
	}{
		{30 * time.Second, "s"},
		{30 * time.Minute, "m"},
		{2*time.Hour + 10*time.Minute, "2h"},
		{49 * time.Hour, "2d"},
	}
	for _, test := range durations {
		if got := FormatDuration(time.Now().Add(test.future)); !strings.Contains(got, test.contains) {
			t.Errorf("FormatDuration(%s) = %q", test.future, got)
		}
	}
	if BoolIcon(true) != "yes" || BoolIcon(false) != "no" {
		t.Fatal("unexpected boolean labels")
	}
	if StatusIcon(true) != "BURNED" || StatusIcon(false) != "ACTIVE" {
		t.Fatal("unexpected status labels")
	}
	if RoleColor("admin") != "admin" || RoleColor("readonly") != "readonly" || RoleColor("user") != "user" {
		t.Fatal("unexpected role labels")
	}
	if ActiveColor(true) != "active" || ActiveColor(false) != "inactive" {
		t.Fatal("unexpected active labels")
	}
	if repeat("ab", 3) != "ababab" || repeat("x", 0) != "" {
		t.Fatal("repeat returned unexpected result")
	}
}
