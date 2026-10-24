package discovery

import (
	"os"
	"regexp"
)

// SelfLabel marks the Sentinels container in compose deployments so it does
// not report its own (intended) Docker socket mount.
const SelfLabel = "io.sentinels.self"

var containerIDRe = regexp.MustCompile(`/containers/([0-9a-f]{64})/`)

// SelfContainerID returns the ID of the container this process runs in, or ""
// on the host. Docker bind-mounts /etc/hostname and friends from
// /var/lib/docker/containers/<id>/, which shows up in mountinfo.
func SelfContainerID(procRoot string) string {
	b, err := os.ReadFile(procRoot + "/self/mountinfo")
	if err != nil {
		return ""
	}
	if m := containerIDRe.FindSubmatch(b); m != nil {
		return string(m[1])
	}
	return ""
}

// IsSelf reports whether c is the Sentinels container itself.
func IsSelf(c Container, selfID string) bool {
	return (selfID != "" && c.ID == selfID) || c.Labels[SelfLabel] == "true"
}
