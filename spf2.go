package libspf2

/*
#cgo LDFLAGS: -L/usr/local/lib -L/usr/lib -lspf2
#cgo CFLAGS: -g -O2 -Wno-error -I/usr/include -I/usr/local/include

#include <stdlib.h>
#include <netdb.h>
#include <spf2/spf.h>
*/
import "C"

import (
	"errors"
	"net"
	"unsafe"
)

const (
	SPFResultINVALID   = Result(C.SPF_RESULT_INVALID)   // (invalid)
	SPFResultPASS      = Result(C.SPF_RESULT_PASS)      // pass
	SPFResultFAIL      = Result(C.SPF_RESULT_FAIL)      // fail
	SPFResultSOFTFAIL  = Result(C.SPF_RESULT_SOFTFAIL)  // softfail
	SPFResultNEUTRAL   = Result(C.SPF_RESULT_NEUTRAL)   // neutral
	SPFResultPERMERROR = Result(C.SPF_RESULT_PERMERROR) // permerror
	SPFResultTEMPERROR = Result(C.SPF_RESULT_TEMPERROR) // temperror
	SPFResultNONE      = Result(C.SPF_RESULT_NONE)      // none
)

type Client interface {
	Query(host string, ip net.IP) (Result, error)
	Close()
}

type clientImpl struct {
	s *C.SPF_server_t
}

// NewClient creates a new SPF client.
func NewClient() Client {
	client := new(clientImpl)
	client.s = C.SPF_server_new(C.SPF_DNS_CACHE, 0)
	return client
}

func (s *clientImpl) Query(host string, ip net.IP) (Result, error) {
	if s.s == nil {
		return SPFResultINVALID, errors.New("client already closed")
	}
	req := newRequest(s)
	defer req.free()
	if err := req.setEnvFrom(host); err != nil {
		return SPFResultINVALID, err
	}
	if err := req.setIpAddr(ip); err != nil {
		return SPFResultINVALID, err
	}
	resp, err := req.query()
	if err != nil {
		return SPFResultNONE, err
	}
	defer resp.free()
	return resp.result(), nil
}

func (s *clientImpl) Close() {
	if s.s != nil {
		C.SPF_server_free(s.s)
		s.s = nil
	}
}

type request struct {
	s *clientImpl
	r *C.SPF_request_t
}

func newRequest(s *clientImpl) *request {
	r := new(request)
	r.s = s
	r.r = C.SPF_request_new(s.s)
	return r
}

// SetIPAddr sets the IP address of the client (sending) MTA
func (r *request) setIpAddr(ip net.IP) error {
	var stat C.SPF_errcode_t
	cstring := C.CString(ip.String())
	defer C.free(unsafe.Pointer(cstring))
	if ip.To4() != nil {
		stat = C.SPF_request_set_ipv4_str(r.r, cstring)
	} else {
		stat = C.SPF_request_set_ipv6_str(r.r, cstring)
	}
	if stat != C.SPF_E_SUCCESS {
		return &spfError{stat}
	}
	return nil
}

// SetEnvFrom sets the envelope from email address from the SMTP MAIL FROM: command
func (r *request) setEnvFrom(from string) error {
	var stat C.int
	cstring := C.CString(from)
	defer C.free(unsafe.Pointer(cstring))
	stat = C.SPF_request_set_env_from(r.r, cstring)
	if stat != C.int(C.SPF_E_SUCCESS) {
		return &spfError{C.SPF_errcode_t(stat)}
	}
	return nil
}

// Query starts the SPF query
func (r *request) query() (*response, error) {
	var stat C.SPF_errcode_t
	var resp *C.SPF_response_t
	stat = C.SPF_request_query_mailfrom(r.r, &resp)
	if stat != C.SPF_E_SUCCESS {
		return nil, &spfError{stat}
	}
	return &response{resp}, nil
}

// Free the request handle
func (r *request) free() {
	if r.r != nil {
		C.SPF_request_free(r.r)
		r.r = nil
	}
}

type response struct {
	r *C.SPF_response_t
}

// Result returns the SPF validation result
func (r *response) result() Result {
	return Result(C.SPF_response_result(r.r))
}

// Free frees the response handle
func (r *response) free() {
	if r.r != nil {
		C.SPF_response_free(r.r)
		r.r = nil
	}
}

type Result int

func (r Result) String() string {
	return C.GoString(C.SPF_strresult(C.SPF_result_t(r)))
}

type spfError struct {
	code C.SPF_errcode_t
}

func (e *spfError) Error() string {
	return C.GoString(C.SPF_strerror(e.code))
}
