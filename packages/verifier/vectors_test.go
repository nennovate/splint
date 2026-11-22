package verifier

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

type vector struct {
	Name   string         `json:"name"`
	Check  string         `json:"check"`
	Status string         `json:"status"`
	Input  map[string]any `json:"input"`
	Expect map[string]any `json:"expect"`
}

// A check gives what it found, in the vector's words, or a refusal.
type check func(in input) (map[string]any, error)

var checks = map[string]check{}

func register(name string, c check) { checks[name] = c }

// TestVectors runs every vector whose check this verifier has, and names the rest.
func TestVectors(t *testing.T) {
	files, err := filepath.Glob("../../spec/vectors/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no vectors found: %v", err)
	}
	ran, skipped := map[string]int{}, map[string]int{}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Vectors []vector `json:"vectors"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		for _, v := range doc.Vectors {
			c, ok := checks[v.Check]
			if !ok || v.Status != "checked" {
				skipped[v.Check]++
				continue
			}
			ran[v.Check]++
			t.Run(filepath.Base(file)+"/"+v.Name, func(t *testing.T) {
				got, err := c(input(v.Input))
				if problem := compare(v.Expect, got, err); problem != "" {
					t.Error(problem)
				}
			})
		}
	}
	t.Logf("ran: %v", summary(ran))
	t.Logf("not covered: %v", summary(skipped))
}

func summary(m map[string]int) []string {
	out := []string{}
	for k, n := range m {
		out = append(out, fmt.Sprintf("%s=%d", k, n))
	}
	sort.Strings(out)
	return out
}

func compare(expect, got map[string]any, err error) string {
	reason, refused := expect["reason"]
	if ok, has := expect["ok"]; has && ok == false {
		refused = true
	}
	if refused {
		if err == nil {
			return fmt.Sprintf("accepted, want refusal %v (got %v)", reason, got)
		}
		if reason != nil && reason != err.Error() {
			return fmt.Sprintf("refused as %q, want %q", err.Error(), reason)
		}
		for k, want := range expect {
			if k == "ok" || k == "reason" {
				continue
			}
			if r, isRefusal := err.(refusedAt); isRefusal && k == "refused_at" {
				if float64(r.at) != want {
					return fmt.Sprintf("refused at %d, want %v", r.at, want)
				}
				continue
			}
			return fmt.Sprintf("refusal lacks %s=%v", k, want)
		}
		return ""
	}
	if err != nil {
		return fmt.Sprintf("refused as %v, want %v", err, expect)
	}
	for k, want := range expect {
		if k == "ok" {
			continue
		}
		g, has := got[k]
		if !has {
			return fmt.Sprintf("result lacks %s, want %v", k, want)
		}
		if !reflect.DeepEqual(normal(g), want) {
			return fmt.Sprintf("%s = %v, want %v", k, normal(g), want)
		}
	}
	return ""
}

// normal turns a result into what encoding/json gives for the vector, so the two compare.
func normal(v any) any {
	raw, err := json.Marshal(v)
	if err != nil {
		return err.Error()
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return err.Error()
	}
	return out
}

// input reads a vector's input, where every value is the vector's own.
type input map[string]any

func (in input) str(k string) string {
	s, _ := in[k].(string)
	return s
}

func (in input) num(k string) int64 {
	n, _ := in[k].(float64)
	return int64(n)
}

func (in input) obj(k string) input {
	m, _ := in[k].(map[string]any)
	return m
}

func (in input) strs(k string) []string {
	list, _ := in[k].([]any)
	out := []string{}
	for _, item := range list {
		s, _ := item.(string)
		out = append(out, s)
	}
	return out
}
