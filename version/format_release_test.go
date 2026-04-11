package version

import "testing"

func TestFormatReleaseVersion(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"v0.68.1-16-g93eb2ab9", "0.68.1"},
		{"0.68.1-16-g93eb2ab9", "0.68.1"},
		{"v0.68.1", "0.68.1"},
		{"0.34.0", "0.34.0"},
		{"development", "development"},
		{"", ""},
		{"  v1.2.3-rc1  ", "1.2.3"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := FormatReleaseVersion(tt.in); got != tt.want {
				t.Fatalf("FormatReleaseVersion(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
