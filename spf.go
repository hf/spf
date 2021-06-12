package spf

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Result int

const (
	None      Result = iota
	Neutral          = iota
	Pass             = iota
	Fail             = iota
	SoftFail         = iota
	TempError        = iota
	PermError        = iota
)

func (r Result) String() string {
	switch r {
	case None:
		return "none"

	case Neutral:
		return "neutral"

	case Pass:
		return "pass"

	case Fail:
		return "fail"

	case SoftFail:
		return "softfail"

	case TempError:
		return "temperror"

	case PermError:
		return "permerror"
	}

	return "<unknown>"
}

type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
	LookupMX(ctx context.Context, host string) ([]*net.MX, error)
	LookupTXT(ctx context.Context, host string) ([]string, error)
}

type Verifier struct {
	// Resolver is the DNS resolver this verifier should use
	Resolver Resolver

	// DefaultPolicy is the default SPF policy to use if there was none found on the domain
	DefaultPolicy string

	// Maximum number of DNS queries
	MaxDNSQueries uint

	// ServerIP is the IP address of the SMTP server
	ServerIP net.IP

	// ClientIP is the IP address of the SMTP client
	ClientIP net.IP

	// FROM is the full address of the MAIL FROM:<addr> command
	FROM string

	// EHLO is the advertized domain in the EHLO/HELO command
	EHLO string

	// SMTP is the domain name of the SMTP service
	SMTP string

	// Timestamp is the timestamp of verification
	Timestamp time.Time
}

var DefaultResolver *net.Resolver = nil

const (
	DefaultPolicy string = "v=spf1 -all exp=github.com/spf"
)

const (
	DefaultMaxDNSQueries uint = 10
)

func NewVerifierWithDefaults() *Verifier {
	return &Verifier{
		Resolver:      DefaultResolver,
		DefaultPolicy: DefaultPolicy,
		MaxDNSQueries: DefaultMaxDNSQueries,

		Timestamp: time.Now(),
	}
}

func (v *Verifier) Check() bool {
	return nil != v.ClientIP && nil != v.ServerIP && "" != v.FROM && "" != v.EHLO && "" != v.SMTP && 0 != v.MaxDNSQueries
}

var v4InV6Prefix = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}

func isV4(ip net.IP) bool {
	return len(ip) == net.IPv4len || len(ip) == net.IPv6len && bytes.HasPrefix(ip, v4InV6Prefix)
}

type Session struct {
	Parent   *Session
	Verifier *Verifier

	Domain string

	// DNSQueries is the number of times a DNS query was executed
	DNSQueries uint

	Mechanisms []string

	Explanation string
}

type PermanentError struct {
	Reason string
	Err    error
}

func (e *PermanentError) Error() string {
	if nil != e.Err {
		return fmt.Sprintf("%v: %T %v", e.Reason, e.Err, e.Err)
	}

	return e.Reason
}

var ErrMaxDNSQueries *PermanentError = &PermanentError{
	Reason: "Maximum number of DNS queries reached",
}

var ErrDomainNotValid *PermanentError = &PermanentError{
	Reason: "Domain name is not valid",
}

var ErrExpandedDomainNotValid *PermanentError = &PermanentError{
	Reason: "Expanded macro yields an invalid domain",
}

var ErrIPInMechanismInvalid *PermanentError = &PermanentError{
	Reason: "IP address in ip4 or ip6 mechanism is not a valid IP address",
}

var ErrDomainEmptyInExistsMechanism *PermanentError = &PermanentError{
	Reason: "Domain in exists mechanism is empty",
}

var ErrDomainEmptyInIncludeMechanism *PermanentError = &PermanentError{
	Reason: "Domain in include mechanism is empty",
}

type TemporaryError struct {
	Reason string
	Err    error
}

func (e *TemporaryError) Error() string {
	if nil != e.Err {
		return fmt.Sprintf("%v: %T %v", e.Reason, e.Err, e.Err)
	}

	return e.Reason
}

func wrapResolverError(err error) error {
	switch err.(type) {
	case *net.DNSError:
		nerr := err.(*net.DNSError)

		if nerr.IsTemporary {
			return &TemporaryError{
				Reason: "DNS query failed temporarily",
				Err:    err,
			}
		}

		return &PermanentError{
			Reason: "DNS query failed permanently",
			Err:    err,
		}
	}

	return &PermanentError{
		Reason: "DNS query failed with unknown error",
		Err:    err,
	}
}

func (s *Session) Reset() {
	s.DNSQueries = 0
	s.Explanation = ""
	s.Mechanisms = nil
}

func (s *Session) Evaluate(ctx context.Context) (Result, error) {
	if !domainRegexp.MatchString(s.Domain) {
		return PermError, ErrDomainNotValid
	}

	if s.DNSQueries >= s.Verifier.MaxDNSQueries {
		return PermError, ErrMaxDNSQueries
	}

	s.DNSQueries += 1

	records, err := s.Verifier.Resolver.LookupTXT(ctx, s.Domain)
	if nil != err {
		rerr := wrapResolverError(err)

		switch err.(type) {
		case *TemporaryError:
			return TempError, rerr
		}

		return PermError, rerr
	}

	for _, record := range records {
		if strings.HasPrefix(record, "v=spf1 ") {
			return s.EvaluatePolicy(ctx, record)
		}
	}

	if "" != s.Verifier.DefaultPolicy {
		return s.EvaluatePolicy(ctx, s.Verifier.DefaultPolicy)
	}

	return None, nil
}

var slashSplitRegexp = regexp.MustCompile(`[/]+`)

func (s *Session) EvaluateMechanism(ctx context.Context, mech string) (bool, error) {
	key := mech
	value := ""
	cidrs := []uint{32, 128}

	colonIdx := strings.Index(mech, ":")
	if colonIdx > -1 {
		key = mech[:colonIdx]
		value = mech[colonIdx+1:]
	}

	if strings.Contains(value, "/") {
		valueParts := slashSplitRegexp.Split(value, -1)

		value = valueParts[0]

		if len(valueParts) > 1 {
			parsed, err := strconv.ParseUint(valueParts[1], 10, 32)
			if nil == err && parsed < 33 {
				cidrs[0] = uint(parsed)
			}
		}

		if len(valueParts) > 2 {
			parsed, err := strconv.ParseUint(valueParts[2], 10, 32)
			if nil == err && parsed < 129 {
				cidrs[1] = uint(parsed)
			}
		}
	}

	network := "ip4"
	if len(s.Verifier.ClientIP) > 4 {
		network = "ip6"
	}

	switch key {
	case "all":
		return true, nil

	case "a":
		domain := s.Domain
		if "" != value {
			expanded, err := s.ExpandMacro(ctx, value, false)
			if nil != err {
				return false, err
			}

			domain = expanded

		}

		if s.DNSQueries >= s.Verifier.MaxDNSQueries {
			return false, ErrMaxDNSQueries
		}

		s.DNSQueries += 1

		ips, err := s.Verifier.Resolver.LookupIP(ctx, network, domain)
		if nil != err {
			return false, wrapResolverError(err)
		}

		for _, ip := range ips {
			match, err := s.checkIP(ctx, ip, cidrs)
			if nil != err {
				return false, err
			}

			if match {
				return true, nil
			}
		}

		return false, nil

	case "mx":
		domain := s.Domain
		if "" != value {
			expanded, err := s.ExpandMacro(ctx, value, false)
			if nil != err {
				return false, err
			}

			domain = expanded
		}

		if s.DNSQueries >= s.Verifier.MaxDNSQueries {
			return false, ErrMaxDNSQueries
		}

		s.DNSQueries += 1

		mxs, err := s.Verifier.Resolver.LookupMX(ctx, domain)
		if nil != err {
			return false, wrapResolverError(err)
		}

		for _, mx := range mxs {
			if s.DNSQueries >= s.Verifier.MaxDNSQueries {
				return false, ErrMaxDNSQueries
			}

			s.DNSQueries += 1

			ips, err := s.Verifier.Resolver.LookupIP(ctx, network, mx.Host)
			if nil != err {
				return false, wrapResolverError(err)
			}

			for _, ip := range ips {
				match, err := s.checkIP(ctx, ip, cidrs)
				if nil != err {
					return false, err
				}

				if match {
					return true, nil
				}
			}
		}

		return false, nil

	case "ip4":
		if 3 != strings.Count(value, ".") {
			return false, ErrIPInMechanismInvalid
		}

		ip := net.ParseIP(value)
		if nil == ip {
			return false, ErrIPInMechanismInvalid
		}

		if !isV4(ip) {
			return false, ErrIPInMechanismInvalid
		}

		return s.checkIP(ctx, ip, cidrs)

	case "ip6":
		if !strings.Contains(value, ":") {
			return false, ErrIPInMechanismInvalid
		}

		ip := net.ParseIP(value)
		if nil == ip {
			return false, ErrIPInMechanismInvalid
		}

		if isV4(ip) {
			return false, ErrIPInMechanismInvalid
		}

		return s.checkIP(ctx, ip, cidrs)

	case "exists":
		if "" == value {
			return false, ErrDomainEmptyInExistsMechanism
		}

		domain, err := s.ExpandMacro(ctx, value, false)
		if nil != err {
			return false, err
		}

		if s.DNSQueries >= s.Verifier.MaxDNSQueries {
			return false, ErrMaxDNSQueries
		}

		s.DNSQueries += 1

		ips, err := s.Verifier.Resolver.LookupIP(ctx, "ip4", domain)
		if nil != err {
			return false, wrapResolverError(err)
		}

		for _, ip := range ips {
			match, err := s.checkIP(ctx, ip, cidrs)
			if nil != err {
				return false, err
			}

			if match {
				return true, nil
			}
		}

		return false, nil

	case "ptr":
		return false, nil

	case "include":
		if "" == value {
			return false, ErrDomainEmptyInIncludeMechanism
		}

		expanded, err := s.ExpandMacro(ctx, value, false)
		if nil != err {
			return false, err
		}

		includeSession := Session{
			Parent:   s,
			Verifier: s.Verifier,

			Domain:     expanded,
			DNSQueries: s.DNSQueries,
		}

		result, err := includeSession.Evaluate(ctx)

		s.DNSQueries = includeSession.DNSQueries

		for _, m := range includeSession.Mechanisms {
			s.Mechanisms = append(s.Mechanisms, m)
		}

		if nil != err {
			return false, err
		}

		if Pass == result {
			return true, nil
		}

		return false, nil
	}

	return false, nil
}

func (s *Session) checkIP(ctx context.Context, ip net.IP, cidrs []uint) (bool, error) {
	a := s.Verifier.ClientIP
	b := ip

	if isV4(a) != isV4(b) {
		return false, nil
	}

	cidr := cidrs[0]

	aoffset := len(v4InV6Prefix)
	boffset := len(v4InV6Prefix)

	if net.IPv4len == len(a) {
		aoffset = 0
	}

	if net.IPv4len == len(b) {
		boffset = 0
	}

	if !isV4(a) {
		aoffset = 0
		boffset = 0
		cidr = cidrs[1]
	}

	upto := int(cidr) / 8
	for i := 0; i < upto; i += 1 {
		if a[aoffset+i] != b[boffset+i] {
			return false, nil
		}
	}

	bits := (0xFF << (8 - (cidr % 8))) & 0xFF

	if 0 != bits {
		return (int(a[aoffset+upto+1]) & bits) == (int(b[boffset+upto+1]) & bits), nil
	}

	return true, nil
}

var policySplitRegexp = regexp.MustCompile(`\s+`)

func (s *Session) EvaluatePolicy(ctx context.Context, policy string) (Result, error) {
	parts := policySplitRegexp.Split(policy, -1)

	for _, part := range parts[1:] {
		if !strings.Contains(part, "=") {
			var qualifier Result = Pass
			mechanism := part

			switch part[0] {
			case '+':
				qualifier = Pass
				mechanism = part[1:]
			case '-':
				qualifier = Fail
				mechanism = part[1:]
			case '~':
				qualifier = SoftFail
				mechanism = part[1:]
			case '?':
				qualifier = Neutral
				mechanism = part[1:]
			}

			matches, err := s.EvaluateMechanism(ctx, mechanism)
			if nil != err {
				switch err.(type) {
				case *TemporaryError:
					return TempError, err
				}

				return PermError, err
			}

			if matches {
				s.Mechanisms = append(s.Mechanisms, part)

				if Fail == qualifier {
					for _, p := range parts[1:] {
						if strings.HasPrefix(p, "exp=") {
							expanded, err := s.ExpandMacro(ctx, p[len("exp="):], true)
							if nil == err {
								s.Explanation = expanded
							}

							break
						}
					}
				}

				return qualifier, nil
			}
		}
	}

	for _, part := range parts[1:] {
		if strings.HasPrefix(part, "redirect=") {
			expanded, err := s.ExpandMacro(ctx, part[len("redirect="):], false)
			if nil != err {
				return PermError, err
			}

			redirectSession := Session{
				Parent:   s,
				Verifier: s.Verifier,

				Domain:     expanded,
				DNSQueries: s.DNSQueries,
			}

			result, err := redirectSession.Evaluate(ctx)

			s.DNSQueries = redirectSession.DNSQueries
			s.Mechanisms = redirectSession.Mechanisms
			s.Explanation = redirectSession.Explanation

			return result, err
		}
	}

	return None, nil
}

var macroRegexp = regexp.MustCompile(`(?i)%(%|_|-|\{([slodiphcrtv])([0-9]*)(r?)([.+,/_=-]*)\})`)

var subdomainPattern = `[^.]{1,63}`
var domainRegexp = regexp.MustCompile(`(?i)^(` + subdomainPattern + `)(\.(` + subdomainPattern + `))*$`)

func (s *Session) ExpandMacro(ctx context.Context, host string, forExplanation bool) (string, error) {
	expanded := macroRegexp.ReplaceAllStringFunc(host, s.macroReplacer)

	if forExplanation {
		return expanded, nil
	}

	if !domainRegexp.MatchString(expanded) {
		return expanded, ErrExpandedDomainNotValid
	}

	return expanded, nil
}

func (s *Session) macroReplacer(m string) string {
	parts := macroRegexp.FindStringSubmatch(m)

	switch parts[1] {
	case "%":
		return "%"
	case "_":
		return " "
	case "-":
		return "%20"
	}

	result := make([]string, 0, 8)

	switch strings.ToLower(parts[2]) {
	case "s":
		return s.Verifier.FROM

	case "l":
		senderSplit := strings.Split(s.Verifier.FROM, "@")
		if 2 == len(senderSplit) {
			return senderSplit[0]
		}

		return m

	case "d":
		domainSplit := strings.Split(s.Domain, ".")
		for _, part := range domainSplit {
			result = append(result, part)
		}

	case "o":
		senderSplit := strings.Split(s.Verifier.FROM, "@")
		if 2 == len(senderSplit) {
			domainSplit := strings.Split(senderSplit[1], ".")
			for _, part := range domainSplit {
				result = append(result, part)
			}
		} else {
			return m
		}

	case "i":
		for _, b := range s.Verifier.ClientIP {
			result = append(result, strconv.FormatUint(uint64(b), 10))
		}

	case "p":
		return m

	case "v":
		if len(s.Verifier.ClientIP) > 4 {
			return "ip6"
		}

		return "in-addr"

	case "h":
		domainSplit := strings.Split(s.Verifier.EHLO, ".")
		for _, part := range domainSplit {
			result = append(result, part)
		}

	case "c":
		return s.Verifier.ClientIP.String()

	case "r":
		domainSplit := strings.Split(s.Verifier.SMTP, ".")
		for _, part := range domainSplit {
			result = append(result, part)
		}

	case "t":
		return strconv.FormatInt(s.Verifier.Timestamp.UTC().Unix(), 10)
	}

	take := len(result)

	if "" != parts[3] {
		parsed, err := strconv.ParseUint(parts[3], 10, 31)
		if nil == err && int(parsed) <= len(result) {
			take = int(parsed)
		}
	}

	if "r" == strings.ToLower(parts[4]) {
		for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
			result[i], result[j] = result[j], result[i]
		}
	}

	delim := "."

	if "" != parts[5] {
		delim = parts[5]
	}

	return strings.Join(result[len(result)-take:], delim)
}
