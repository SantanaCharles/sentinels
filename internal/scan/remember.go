package scan

import (
	"context"

	"github.com/SantanaCharles/sentinels/internal/store"
)

// Remember compares res with the store, flags new findings and lists the ones
// that disappeared since the previous scan.
func Remember(ctx context.Context, st *store.Store, res *Result) error {
	diff, err := st.RecordScan(ctx, res.Started, res.Findings)
	if err != nil {
		return err
	}
	accepted, err := st.AcceptedFindings(ctx)
	if err != nil {
		return err
	}
	isNew := map[string]bool{}
	for _, f := range diff.New {
		isNew[f.Key()] = true
	}
	for i := range res.Findings {
		f := &res.Findings[i]
		f.New = isNew[f.Key()]
		f.Accepted = accepted[f.Key()]
	}
	res.History = &History{New: len(diff.New), Resolved: diff.Resolved, First: diff.First}
	return nil
}
