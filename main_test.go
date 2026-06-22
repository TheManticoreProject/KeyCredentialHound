package main

import "testing"

func TestCrossCollectorOutputFile(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"json extension", "20060102150405_keycredentials.json", "20060102150405_keycredentials_cross_collector.json"},
		{"no extension", "output", "output_cross_collector"},
		{"path with directories", "out/dir/graph.json", "out/dir/graph_cross_collector.json"},
		{"other extension", "graph.txt", "graph_cross_collector.txt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := crossCollectorOutputFile(tt.input)
			if got != tt.expected {
				t.Errorf("crossCollectorOutputFile(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
