package bootz

import (
	"fmt"
	"net/url"

	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/logger"
	"github.com/coredhcp/coredhcp/plugins"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
)

var log = logger.GetLogger("plugins/bootz")

var Plugin = plugins.Plugin{
	Name:   "bootz",
	Setup4: setup4,
	Setup6: setup6,
}

const (
	OPTION_V4_SZTP_REDIRECT uint8 = 143
	OPTION_V6_SZTP_REDIRECT uint8 = 136
)

var (
	ztpV4Opt *dhcpv4.Option
	ztpV6Opt dhcpv6.Option
)

func parseArgs(args ...string) (*url.URL, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("exactly one argument must be passed to BootZ plugin, got %d", len(args))
	}
	return url.Parse(args[0])
}

func setup4(args ...string) (handler.Handler4, error) {
	url, err := parseArgs(args...)
	if err != nil {
		return nil, err
	}
	ztpV4Opt = &dhcpv4.Option{
		Code:  dhcpv4.GenericOptionCode(OPTION_V4_SZTP_REDIRECT),
		Value: dhcpv4.String(url.String()),
	}
	return handler4, nil
}

func setup6(args ...string) (handler.Handler6, error) {
	url, err := parseArgs(args...)
	if err != nil {
		return nil, err
	}
	ztpV6Opt = &dhcpv6.OptionGeneric{
		OptionCode: dhcpv6.OptionCode(OPTION_V6_SZTP_REDIRECT),
		OptionData: []byte(url.String()),
	}
	return handler6, nil
}

func handler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	for _, p := range req.ParameterRequestList() {
		if p.Code() == OPTION_V4_SZTP_REDIRECT {
			resp.Options.Update(*ztpV4Opt)
			log.Debugf("Added ZTP option: %v", resp.Summary())
			break
		}
	}
	return resp, false
}

func handler6(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	decap, err := req.GetInnerMessage()
	if err != nil {
		log.Errorf("Could not decapsulate request: %v", err)
		return nil, false
	}

	for _, code := range decap.Options.RequestedOptions() {
		if code == ztpV6Opt.Code() {
			resp.AddOption(ztpV6Opt)
			log.Debugf("Added ZTP option: %v", resp.Summary())
		}
	}
	return resp, false
}
