// +build !go1.16

package soju

import (
	"strings"
)

func isErrClosed(err error) bool {
	return err != nil && strings.Contains(err.Error(), "use of closed network connection")
}
