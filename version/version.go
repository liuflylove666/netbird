package version

import (
	"regexp"
	"strings"

	v "github.com/hashicorp/go-version"
)

// will be replaced with the release version when using goreleaser
var version = "development"

var (
	VersionRegexp = regexp.MustCompile("^" + v.VersionRegexpRaw + "$")
	SemverRegexp  = regexp.MustCompile("^" + v.SemverRegexpRaw + "$")
	// releaseCoreRegexp captures MAJOR.MINOR.PATCH at the start (strips git describe / prerelease tail).
	releaseCoreRegexp = regexp.MustCompile(`^v?(\d+\.\d+\.\d+)`)
)

// NetbirdVersion returns the Netbird version
func NetbirdVersion() string {
	return version
}

// FormatReleaseVersion returns the public release number without git describe or prerelease suffix
// (e.g. "v0.68.1-16-g93eb2ab9" -> "0.68.1"). Unchanged if no semver core is found or value is "development".
func FormatReleaseVersion(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "development" {
		return s
	}
	m := releaseCoreRegexp.FindStringSubmatch(s)
	if len(m) < 2 {
		return s
	}
	return m[1]
}
