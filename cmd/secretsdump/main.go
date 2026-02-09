package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/atoz-project/go-secretsdump/pkg/ntds"
	"github.com/atoz-project/go-secretsdump/pkg/sam"
)

func main() {
	ntdsPath := flag.String("ntds", "", "path to ntds.dit file")
	systemPath := flag.String("system", "", "path to SYSTEM hive file")
	samPath := flag.String("sam", "", "path to SAM hive file")
	flag.Parse()

	if *systemPath == "" {
		fmt.Fprintln(os.Stderr, "error: -system flag is required")
		flag.Usage()
		os.Exit(1)
	}

	if *ntdsPath == "" && *samPath == "" {
		fmt.Fprintln(os.Stderr, "error: either -ntds or -sam flag is required")
		flag.Usage()
		os.Exit(1)
	}

	if err := run(*ntdsPath, *systemPath, *samPath); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(ntdsPath, systemPath, samPath string) error {
	if samPath != "" {
		return dumpSAM(samPath, systemPath)
	}
	return dumpNTDS(ntdsPath, systemPath)
}

func dumpSAM(samPath, systemPath string) error {
	samFile, err := os.Open(samPath)
	if err != nil {
		return fmt.Errorf("open SAM: %w", err)
	}
	defer samFile.Close()

	systemFile, err := os.Open(systemPath)
	if err != nil {
		return fmt.Errorf("open SYSTEM: %w", err)
	}
	defer systemFile.Close()

	reader, err := sam.Open(samFile, systemFile)
	if err != nil {
		return fmt.Errorf("sam open: %w", err)
	}

	hashes, err := reader.DumpAll()
	if err != nil {
		return fmt.Errorf("sam dump: %w", err)
	}

	for _, h := range hashes {
		fmt.Printf("%s:%d:%s:%s:::\n",
			h.Username, h.RID,
			hex.EncodeToString(h.LMHash),
			hex.EncodeToString(h.NTHash))
	}
	return nil
}

func dumpNTDS(ntdsPath, systemPath string) error {
	systemData, err := os.ReadFile(systemPath)
	if err != nil {
		return fmt.Errorf("read SYSTEM: %w", err)
	}

	bootKey, err := sam.ExtractBootKey(systemData)
	if err != nil {
		return fmt.Errorf("extract boot key: %w", err)
	}

	ditFile, err := os.Open(ntdsPath)
	if err != nil {
		return fmt.Errorf("open ntds.dit: %w", err)
	}
	defer ditFile.Close()

	reader, err := ntds.Open(ditFile, bootKey)
	if err != nil {
		return fmt.Errorf("ntds open: %w", err)
	}
	defer reader.Close()

	ctx := context.Background()
	for {
		hash, err := reader.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("ntds next: %w", err)
		}
		fmt.Printf("%s:%d:%s:%s:::\n",
			hash.Username, hash.RID,
			hex.EncodeToString(hash.LMHash),
			hex.EncodeToString(hash.NTHash))
	}
	return nil
}
