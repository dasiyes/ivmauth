package ivmanto

import "net/url"

// RequestSpec holds the requests' attributes for authentication
type RequestSpec struct {
	Body     []byte
	Origin   url.URL
	Location UNLocode
}
