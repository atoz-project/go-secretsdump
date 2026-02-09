package ese_test

import (
	"context"
	"io"
	"os"
	"testing"

	"github.com/atoz-project/go-secretsdump/pkg/ese"
)

func TestOpenAndIterate(t *testing.T) {
	f, err := os.Open("testdata/ntds.dit")
	if err != nil {
		t.Skip("testdata/ntds.dit not found:", err)
	}
	defer f.Close()

	db, err := ese.Open(f)
	if err != nil {
		t.Fatal("Open:", err)
	}

	cursor, err := db.OpenTable("datatable")
	if err != nil {
		t.Fatal("OpenTable:", err)
	}

	ctx := context.Background()
	count := 0
	for {
		rec, err := cursor.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal("Next:", err)
		}
		_ = rec
		count++
	}

	if count == 0 {
		t.Fatal("expected records from datatable, got 0")
	}
	t.Logf("datatable: %d records", count)
}
