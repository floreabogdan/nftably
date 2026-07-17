//go:build !unix

package main

// adoptDBOwnership is a Unix concern: there is no service user to hand the
// database to on other platforms (and no nftables either — this build path
// exists only so nftably compiles on a developer's machine).
func adoptDBOwnership(string) {}
