package dhcp

import (
	"fmt"
	"os"
	"text/template"

	cdconfig "github.com/coredhcp/coredhcp/config"
	cdplugins "github.com/coredhcp/coredhcp/plugins"
	cdserver "github.com/coredhcp/coredhcp/server"

	plfile "github.com/coredhcp/coredhcp/plugins/file"
	plnetmask "github.com/coredhcp/coredhcp/plugins/netmask"
	plrouter "github.com/coredhcp/coredhcp/plugins/router"
	plbootz "github.com/openconfig/bootz/dhcp/plugins"

	log "github.com/golang/glog"
)

const confTemplate = `
# CoreDHCP configuration (yaml)
server4:
  plugins:
    - router: {{ .Gateway }}
    - netmask: {{ .Netmask }}
    - file: {{ .LeaseFile }}
    - bootz: {{ .BootzSrv }}
`

var desiredPlugins = []*cdplugins.Plugin{
	&plfile.Plugin,
	&plnetmask.Plugin,
	&plrouter.Plugin,
	&plbootz.Plugin,
}

type dhcpServer struct {
	config    *cdconfig.Config
	server    *cdserver.Servers
	leaseFile string
}

type DHCPServerConfig struct {
	StaticAddresses map[string]string
	Gateway         string
	Netmask         string
	BootzServerAddr string
}

func New(conf *DHCPServerConfig) *dhcpServer {
	leaseFile, err := os.CreateTemp("", "coredhcp_leases_*.txt")
	if err != nil {
		log.Fatalf("Failed to create lease file: %v", err)
	}

	for mac, ip := range conf.StaticAddresses {
		leaseFile.WriteString(fmt.Sprintf("%s %s\n", mac, ip))
	}
	leaseFile.Close()

	confFile, err := os.CreateTemp("", "coredhcp_conf_*.yml")
	if err != nil {
		log.Fatalf("Failed to create configuration file: %v", err)
	}
	defer os.Remove(confFile.Name())

	confTmpl, err := template.New("coredhcp_conf").Parse(confTemplate)

	if err != nil {
		log.Fatalf("Error parsing configuraiton template: %v", err)
	}

	confTmpl.Execute(confFile, struct {
		Gateway   string
		Netmask   string
		LeaseFile string
		BootzSrv  string
	}{
		Gateway:   conf.Gateway,
		Netmask:   conf.Netmask,
		LeaseFile: leaseFile.Name(),
		BootzSrv:  conf.BootzServerAddr,
	})

	config, err := cdconfig.Load(confFile.Name())
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	for _, plugin := range desiredPlugins {
		if err := cdplugins.RegisterPlugin(plugin); err != nil {
			log.Fatalf("Failed to register plugin '%s': %v", plugin.Name, err)
		}
	}

	return &dhcpServer{
		config:    config,
		leaseFile: leaseFile.Name(),
	}
}

func (dhcp *dhcpServer) Start() {
	srv, err := cdserver.Start(dhcp.config)
	if err != nil {
		log.Fatalf("Error starting DHCP server: %v", err)
	}
	dhcp.server = srv
}

func (dhcp *dhcpServer) Stop() {
	if dhcp.server != nil {
		dhcp.server.Close()
		if err := dhcp.server.Wait(); err != nil {
			log.Warningln(err)
		}
	}
	os.Remove(dhcp.leaseFile)
}
