package version

import (
	"regexp"
	"runtime/debug"
	"strings"

	v "github.com/hashicorp/go-version"
)

// DevelopmentVersion is the value of NetbirdVersion() for non-release builds.
// Wire-format consumers (management server, dashboard) match against this
// string, so it must not change without coordinating those consumers.
const DevelopmentVersion = "development"

// will be replaced with the release version when using goreleaser
var version = DevelopmentVersion

var (
	VersionRegexp = regexp.MustCompile("^" + v.VersionRegexpRaw + "$")
	SemverRegexp  = regexp.MustCompile("^" + v.SemverRegexpRaw + "$")
	// releaseCoreRegexp captures MAJOR.MINOR.PATCH at the start (strips git describe / prerelease tail).
	releaseCoreRegexp = regexp.MustCompile(`^v?(\d+\.\d+\.\d+)`)
)

// NetbirdVersion returns the Netbird version. For non-release builds the
// value is the literal DevelopmentVersion constant; the VCS revision is
// exposed separately via NetbirdCommit so the wire format stays stable.
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

// NetbirdCommit returns the VCS revision (truncated to 12 chars) of the
// build, with a "-dirty" suffix when the working tree was modified.
// Returns an empty string when no build info is embedded (e.g. release
// builds compiled by goreleaser without -buildvcs).
func NetbirdCommit() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}

	var revision string
	var modified bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}

	if revision == "" {
		return ""
	}

	if len(revision) > 12 {
		revision = revision[:12]
	}

	if modified {
		revision += "-dirty"
	}
	return revision
}

// IsDevelopmentVersion reports whether the given version string identifies
// a non-release / development build. It is the single source of truth for
// "is this a dev build" checks across the codebase; use it instead of
// comparing against the "development" literal or ad-hoc substring checks.
//
// Matches the bare DevelopmentVersion constant as well as any future
// extension such as "development-<sha>" or "development-<sha>-dirty",
// while excluding tagged prereleases like "v0.31.1-dev".
func IsDevelopmentVersion(v string) bool {
	return strings.HasPrefix(v, DevelopmentVersion)
}
