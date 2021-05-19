// +build go1.16

package soju

import (
	"errors"
	"net"
)

func isErrClosed(err error) bool {
	return errors.Is(err, net.ErrClosed)
}
