package cli

import (
	"io"

	"github.com/spf13/cobra"

	"github.com/hidetzu/reelwarden/internal/decision"
	"github.com/hidetzu/reelwarden/internal/model"
	"github.com/hidetzu/reelwarden/internal/report"
	"github.com/hidetzu/reelwarden/internal/version"
)

func newReportCmd(streams IO) *cobra.Command {
	var format, output, policy string
	cmd := &cobra.Command{
		Use:   "report <scan.json>",
		Short: "Show groups, evidence, keep/review decisions and space estimates",
		Example: `  reelwarden report scan.json
  reelwarden report scan.json --format csv --output report.csv`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != report.FormatTable && format != report.FormatJSON && format != report.FormatCSV {
				return usageErr("--format must be table, json or csv")
			}
			res, err := loadScan(args[0])
			if err != nil {
				return err
			}
			ev, err := decision.Evaluate(res, policy)
			if err != nil {
				return usageErr("%v", err)
			}
			return writeOutput(output, scanGuard(res, args[0]), streams.Out, func(w io.Writer) error {
				return report.Write(w, format, res, ev, args[0], version.Info())
			})
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", report.FormatTable, "table, json or csv")
	cmd.Flags().StringVarP(&output, "output", "o", "", "write to file (default: stdout)")
	cmd.Flags().StringVar(&policy, "policy", model.PolicyConservative, "conservative, or balanced (experimental: also proposes re-encodes; audio is not compared)")
	return cmd
}

func newPlanCmd(streams IO) *cobra.Command {
	var output, policy string
	cmd := &cobra.Command{
		Use:   "plan <scan.json>",
		Short: "Write a read-only cleanup plan with preconditions and warnings (nothing is executed)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := loadScan(args[0])
			if err != nil {
				return err
			}
			ev, err := decision.Evaluate(res, policy)
			if err != nil {
				return usageErr("%v", err)
			}
			p := decision.BuildPlan(res, ev, args[0], version.Info())
			return writeOutput(output, scanGuard(res, args[0]), streams.Out, func(w io.Writer) error { return writeJSON(w, p) })
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "write the plan JSON here (default: stdout)")
	cmd.Flags().StringVar(&policy, "policy", model.PolicyConservative, "conservative, or balanced (experimental: also proposes re-encodes; audio is not compared)")
	return cmd
}

func newVersionCmd(streams IO) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := io.WriteString(streams.Out, version.String()+"\n")
			return err
		},
	}
}

// scanGuard protects the paths and extensions recorded in a scan result.
func scanGuard(res *model.ScanResult, input string) outputGuard {
	return outputGuard{exts: res.Params.Extensions, res: res, input: input}
}
