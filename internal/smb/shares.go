package smb

import (
	"fmt"
	"os"
	"slices"
	"strings"
)

var defaultSkippedShares = []string{"IPC$", "PRINT$"}

func IsAdministrativeShare(name string) bool {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "ADMIN$", "C$", "IPC$", "PRINT$":
		return true
	default:
		return false
	}
}

func IsADShare(name string) bool {
	_, ok := ADShareType(name)
	return ok
}

func ADShareType(name string) (string, bool) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "SYSVOL":
		return "sysvol", true
	case "NETLOGON":
		return "netlogon", true
	default:
		return "", false
	}
}

func (c *Client) ListShares() ([]ShareInfo, error) {
	session, _, err := c.connectedSession()
	if err != nil {
		return nil, err
	}

	guard := c.beginOperation()
	shares, err := session.ListSharenames()
	err = guard.finish(err)
	if err != nil {
		return nil, fmt.Errorf("list shares: %w", err)
	}

	accessible := make([]ShareInfo, 0, len(shares))
	for _, share := range shares {
		if share == "" || slices.Contains(defaultSkippedShares, strings.ToUpper(share)) {
			continue
		}

		if err := c.checkShareAccess(share); err != nil {
			if IsTimeoutError(err) {
				return nil, fmt.Errorf("check access %s: %w", share, err)
			}
			if isPermissionError(err) {
				continue
			}
			continue
		}

		accessible = append(accessible, ShareInfo{
			Name:        share,
			Description: "",
			Type:        inferShareType(share),
		})
	}

	return accessible, nil
}

func (c *Client) checkShareAccess(share string) error {
	fs, err := c.mountShareWithDeadline(share)
	if err != nil {
		return err
	}
	defer c.umountShareWithDeadline(fs)

	guard := c.beginOperation()
	_, err = fs.ReadDir("")
	err = guard.finish(err)
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	return err
}

func inferShareType(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if adType, ok := ADShareType(name); ok {
		return adType
	}
	upper := strings.ToUpper(name)
	switch {
	case upper == "IPC$":
		return "ipc"
	case upper == "PRINT$":
		return "print"
	case strings.HasSuffix(name, "$"):
		return "disk-hidden"
	default:
		return "disk"
	}
}
