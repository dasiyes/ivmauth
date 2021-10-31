package authenticating

import (
	b64 "encoding/base64"
	"fmt"
	"strings"
)

// getXClient - retrievs the ClientID and Client Secret from the provided xic string that represents the ClientID and ClientSecret as Basic auth string.
func getXClient(xic string) (cid string, csc string) {

	// TODO: remove after debug
	fmt.Printf("xic: %v\n", xic)

	cis := strings.Split(xic, " ")
	if len(cis) != 2 || cis[0] != "Basic" {
		return "", ""
	}

	//dc, err := base64url.Decode(cis[1])
	dc, err := b64.URLEncoding.DecodeString(cis[1])
	if err != nil {
		return "", ""
	}

	cp := strings.Split(string(dc), ":")
	if len(cp) == 1 {
		return "", ""
	}

	return cp[0], cp[1]
}
