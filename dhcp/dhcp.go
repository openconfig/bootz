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
	epb "github.com/openconfig/bootz/server/entitymanager/proto/entity"

	log "github.com/golang/glog"
)

const confTemplate = `
# CoreDHCP configuration (yaml)
server4:
  plugins:
    - router: {{ .Gateway }}
    - netmask: {{ .Netmask }}
    - file: {{ .LeaseFile }}
    - bootz: {{ .BootzServer }}
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

type DHCPEntityManager interface {
	GetDHCPConfig() []*epb.DHCPConfig
}

func New(em DHCPEntityManager) (*dhcpServer, error) {
	leaseFile, err := os.CreateTemp("", "coredhcp_leases_*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create lease file: %v", err)
	}

	//TODO: support for per-device gw+bootzServer?
	gateway, netmask, bootzSrv := "", "", ""
	conf := em.GetDHCPConfig()
	for _, d := range conf {
		leaseFile.WriteString(fmt.Sprintf("%s %s\n", d.GetHardwareAddress(), d.GetIp()))
		gateway = d.Gateway
		netmask = d.Netmask
		bootzSrv = d.Bootzserver
	}
	leaseFile.Close()

	confFile, err := os.CreateTemp("", "coredhcp_conf_*.yml")
	if err != nil {
		return nil, fmt.Errorf("failed to create configuration file: %v", err)
	}
	defer os.Remove(confFile.Name())

	confTmpl, err := template.New("coredhcp_conf").Parse(confTemplate)

	if err != nil {
		return nil, fmt.Errorf("Error parsing configuraiton template: %v", err)
	}

	confTmpl.Execute(confFile, struct {
		Gateway     string
		Netmask     string
		LeaseFile   string
		BootzServer string
	}{
		Gateway:     gateway,
		Netmask:     netmask,
		LeaseFile:   leaseFile.Name(),
		BootzServer: bootzSrv,
	})

	config, err := cdconfig.Load(confFile.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %v", err)
	}

	for _, plugin := range desiredPlugins {
		if err := cdplugins.RegisterPlugin(plugin); err != nil {
			return nil, fmt.Errorf("failed to register plugin '%s': %v", plugin.Name, err)
		}
	}

	return &dhcpServer{
		config:    config,
		leaseFile: leaseFile.Name(),
	}, nil
}

func (dhcp *dhcpServer) Start() error {
	srv, err := cdserver.Start(dhcp.config)
	if err != nil {
		return fmt.Errorf("error starting DHCP server: %v", err)
	}
	dhcp.server = srv
	return nil
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
