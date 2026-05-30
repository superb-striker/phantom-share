package output

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
)

var (
	successColor = color.New(color.FgGreen, color.Bold)
	infoColor    = color.New(color.FgCyan)
	warnColor    = color.New(color.FgYellow)
	errorColor   = color.New(color.FgRed, color.Bold)
	dimColor     = color.New(color.FgHiBlack)
	boldColor    = color.New(color.Bold)
	highlightColor = color.New(color.FgHiCyan, color.Bold)
)

func Success(format string, a ...any) {
	successColor.Fprintf(os.Stdout, "Success: "+format+"\n", a...)
}

func Info(format string, a ...any) {
	infoColor.Fprintf(os.Stdout, "Info: "+format+"\n", a...)
}

func Warn(format string, a ...any) {
	warnColor.Fprintf(os.Stdout, "Warning: "+format+"\n", a...)
}

func Error(format string, a ...any) {
	errorColor.Fprintf(os.Stderr, "Error: "+format+"\n", a...)
}

func Header(title string) {
	fmt.Println()
	boldColor.Println("  " + title)
	dimColor.Println("  " + repeat("─", len(title)+2))
}

func Field(label, value string) {
	dimColor.Fprintf(os.Stdout, "  %-22s", label+":")
	fmt.Println(" " + value)
}

func FieldHighlight(label, value string) {
	dimColor.Fprintf(os.Stdout, "  %-22s", label+":")
	highlightColor.Println(" " + value)
}

func Divider() {
	dimColor.Println("  " + repeat("─", 56))
}

func SecretBox(content string) {
	Divider()
	fmt.Println()
	fmt.Println(content)
	fmt.Println()
	Divider()
}

func Banner() {
	c := color.New(color.FgMagenta, color.Bold)
	c.Println(`
  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝`)
	dimColor.Println("Secure secret sharing")
}

// Creates a styled tablewriter table writing to w.
func NewTable(w io.Writer, headers []string) *tablewriter.Table {
	t := tablewriter.NewWriter(w)
	t.SetHeader(headers)
	t.SetBorder(false)
	t.SetColumnSeparator("│")
	t.SetHeaderLine(true)
	t.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	t.SetAlignment(tablewriter.ALIGN_LEFT)
	t.SetTablePadding("  ")
	t.SetNoWhiteSpace(false)
	colors := make([]tablewriter.Colors, len(headers))
	for i := range colors {
		colors[i] = tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiCyanColor}
	}
	t.SetHeaderColor(colors...)	
	return t
}


func FormatTime(t time.Time) string {
	return t.Local().Format("2006-01-02 15:04:05")
}

func FormatDuration(t time.Time) string {
	now := time.Now()
	if t.Before(now) {
		return color.RedString("expired")
	}
	d := time.Until(t)
	switch {
	case d < time.Minute:
		return color.YellowString("%ds", int(d.Seconds()))
	case d < time.Hour:
		return color.YellowString("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return color.GreenString("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return color.GreenString("%dd %dh", int(d.Hours()/24), int(d.Hours())%24)
	}
}

func BoolIcon(b bool) string {
	if b {
		return color.GreenString("yes")
	}
	return color.HiBlackString("no")
}

func StatusIcon(viewed bool) string {
	if viewed {
		return color.RedString("BURNED")
	}
	return color.GreenString("ACTIVE")
}

func RoleColor(role string) string {
	switch role {
	case "admin":
		return color.New(color.FgRed, color.Bold).Sprint(role)
	case "readonly":
		return color.HiBlackString(role)
	default:
		return color.CyanString(role)
	}
}

func ActiveColor(active bool) string {
	if active {
		return color.GreenString("active")
	}
	return color.RedString("inactive")
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}