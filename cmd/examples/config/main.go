package main

import (
	"context"
	"flag"
	"log"
	"time"

	osquery "github.com/Uptycs/basequery-go"
	gen "github.com/Uptycs/basequery-go/gen/osquery"
	"github.com/Uptycs/basequery-go/plugin/config"
)

var (
	verbose  = flag.Bool("verbose", false, "Log verbose")
	socket   = flag.String("socket", "", "Path to the extensions UNIX domain socket")
	timeout  = flag.Int("timeout", 5, "Seconds to wait for autoloaded extensions")
	interval = flag.Int("interval", 5, "Seconds delay between connectivity checks")
)

func main() {
	flag.Parse()

	if *socket == "" {
		log.Fatalln("Missing required --socket argument")
	}

	serverTimeout := osquery.ServerTimeout(
		time.Second * time.Duration(*timeout),
	)
	serverPingInterval := osquery.ServerPingInterval(
		time.Second * time.Duration(*interval),
	)

	server, err := osquery.NewExtensionManagerServer(
		"example_extension",
		*socket,
		serverTimeout,
		serverPingInterval,
	)

	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}
	server.RegisterPlugin(config.NewPlugin("example_config", GenerateConfigs, RefreshConfig))
	log.Println("Starting config extension")
	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

// RefreshConfig callback function invoked when config is refreshed.
func RefreshConfig(ctx context.Context, request gen.ExtensionPluginRequest) gen.ExtensionResponse {
	log.Println("Example config extension got refresh request")
	for k, v := range request {
		log.Println(k, v)
	}
	return gen.ExtensionResponse{
		Status: &gen.ExtensionStatus{Code: 0, Message: "OK"},
	}
}

// GenerateConfigs callback function invoked to get the config.
func GenerateConfigs(ctx context.Context) (map[string]string, error) {
	log.Println("Sending example extension config")
	return map[string]string{
		"config1": `
{
  "options1": {
    "host_identifier": "hostname",
    "schedule_splay_percent": 10
  },
  "schedule1": {
    "macos_kextstat": {
      "query": "SELECT * FROM kernel_extensions;",
      "interval": 10
    },
    "foobar": {
      "query": "SELECT foo, bar, pid FROM foobar_table;",
      "interval": 600
    }
  }
}
`,
	}, nil
}
