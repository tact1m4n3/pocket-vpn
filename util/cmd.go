package util

import "os/exec"

func RunCommand(name string, args ...string) bool {
	cmd := exec.Command(name, args...)
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}
