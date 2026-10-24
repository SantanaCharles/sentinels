//go:build !unix

package config

import "os"

func copyOwner(string, os.FileInfo) {}
