package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Check the real mappings before counting them: a row naming a missing test
// must never contribute to a green README badge.
func TestReadmeChecklistBadge(t *testing.T) {
	root := filepath.Join("..", "..")
	file := filepath.Join(root, "CHECKLIST.md")
	var out bytes.Buffer
	if code := run(append([]string{"-file", file}, checklistDirs(t, root)...), &out, &out); code != 0 {
		t.Fatalf("invalid checklist (exit %d):\n%s", code, out.String())
	}
	items, err := parseChecklist(file, func(format string, args ...any) {
		t.Errorf(format, args...)
	})
	if err != nil {
		t.Fatal(err)
	}
	mapped := 0
	for _, it := range items {
		if !it.na {
			mapped++
		}
	}
	readme, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("[![Checklist: %d/%d mapped](https://img.shields.io/badge/checklist-%d%%2F%d%%20mapped-blue)](CHECKLIST.md)",
		mapped, len(items), mapped, len(items))
	if !strings.Contains(string(readme), want) {
		t.Fatalf("stale or missing README checklist badge; want:\n%s", want)
	}
}

// checklistDirs returns the package directories that CI passes to the checklist
// command, so the badge counts exactly the mappings CI checks.
func checklistDirs(t *testing.T, root string) []string {
	t.Helper()
	ci, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(ci), "\n") {
		value, ok := strings.CutPrefix(strings.TrimSpace(line), "checklist-dirs: ")
		if !ok {
			continue
		}
		var dirs []string
		if err := json.Unmarshal([]byte(strings.Trim(value, "'")), &dirs); err != nil || len(dirs) == 0 {
			t.Fatalf("ci.yml checklist-dirs %s: %v", value, err)
		}
		for i, d := range dirs {
			dirs[i] = filepath.Join(root, d)
		}
		return dirs
	}
	t.Fatal("ci.yml passes no checklist-dirs")
	return nil
}
