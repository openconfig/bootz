package plugins

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

type DHCPResponse uint8

const (
	OPTION_V4_SZTP_REDIRECT DHCPResponse = 136
	OPTION_V6_SZTP_REDIRECT DHCPResponse = 143
)

var (
	opt136 *dhcpv4.Option
	opt143 dhcpv6.Option
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
	opt := dhcpv4.OptGeneric(dhcpv4.GenericOptionCode(OPTION_V4_SZTP_REDIRECT), []byte(url.String()))
	opt136 = &opt
	log.Printf("Loaded plugin for bootZ.")
	return bootzHandler4, nil
}

func setup6(args ...string) (handler.Handler6, error) {
	url, err := parseArgs(args...)
	if err != nil {
		return nil, err
	}
	opt := dhcpv6.OptionGeneric{
		OptionCode: dhcpv6.OptionCode(OPTION_V6_SZTP_REDIRECT),
		OptionData: []byte(url.String()),
	}
	opt143 = &opt
	log.Printf("Loaded plugin for bootZ.")
	return bootzHandler6, nil
}

func bootzHandler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	log.Debugf("Received DHCPv4 packet: %s", req.Summary())
	if opt136 == nil {
		return resp, true
	}
	if req.IsOptionRequested(opt136.Code) {
		resp.Options.Update(*opt136)
		log.Debugf("Added BootZ %s to request", opt136)
	}
	return resp, true
}

func bootzHandler6(req, resp dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
	log.Debugf("Received DHCPv4 packet: %s", req.Summary())
	if opt143 == nil {
		return resp, true
	}

	decap, err := req.GetInnerMessage()
	if err != nil {
		log.Errorf("Could not decapsulate request: %v", err)
		return nil, true
	}

	for _, code := range decap.Options.RequestedOptions() {
		if code == opt143.Code() {
			resp.AddOption(opt143)
			log.Debugf("Added BootZ %s to request", opt136)
		}
	}
	return resp, true
}
