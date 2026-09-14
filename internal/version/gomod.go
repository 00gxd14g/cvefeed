package version

// compareGoMod orders Go module versions.
//
// The Go Modules Reference defines them as semantic versions with a "v" prefix,
// so the ordering is semver's and nothing more is implemented here. Two Go
// specific shapes fall out of that definition rather than needing rules:
//
//   - A pseudo-version, v0.0.0-20191109021931-daa7c04131f5, is a pre-release of
//     its base version. Semver clause 9 puts it below the base, which is what
//     "no tagged release yet" means, and two pseudo-versions of the same base
//     order by their fixed-width UTC timestamps.
//   - "+incompatible" is build metadata. Clause 10 ignores build metadata for
//     precedence, so v2.0.0+incompatible and v2.0.0 are one version here, which
//     is also what golang.org/x/mod/semver reports.
func compareGoMod(a, b string) (int, Certainty, bool) {
	return compareSemver(a, b)
}
