// Package buildinfo holds nftably's version string.
package buildinfo

// Version is the build version. The release build overrides it with the git
// tag via -ldflags "-X github.com/floreabogdan/nftably/internal/buildinfo.Version=...".
// A source build leaves it at this default.
var Version = "0.1.3-dev"

// Commit is the git SHA the release build was cut from; empty on a source build.
// Set via -ldflags "-X github.com/floreabogdan/nftably/internal/buildinfo.Commit=...".
var Commit = ""
