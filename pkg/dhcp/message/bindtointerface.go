package message

import (
	"github.com/insomniacslk/dhcp/interfaces"
)

// BindToInterface (deprecated) redirects to interfaces.BindToInterface
func BindToInterface(fd int, ifname string) error {
	return interfaces.BindToInterface(fd, ifname)
}
