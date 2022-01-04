package main

import (
	"context"
	"flag"
	"log"
	"strconv"
	"time"

	osquery "github.com/Uptycs/basequery-go"
	"github.com/Uptycs/basequery-go/plugin/table"
)

var (
	//lint:ignore U1000 Argument is required by basequery
	verbose  = flag.Bool("verbose", false, "Verbose mode")
	socket   = flag.String("socket", "", "Path to the extensions UNIX domain socket")
	timeout  = flag.Int("timeout", 3, "Seconds to wait for autoloaded extensions")
	interval = flag.Int("interval", 3, "Seconds delay between connectivity checks")
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
	serverPromPort := osquery.ServerPrometheusPort(3000)

	server, err := osquery.NewExtensionManagerServer(
		"events_extension",
		*socket,
		serverTimeout,
		serverPingInterval,
		serverPromPort,
	)

	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}
	server.RegisterPlugin(table.NewPlugin("example_events", ExampleEventsColumns(), ExampleEventsGenerate))

	go func() {
		time.Sleep(time.Second * 5)
		client, _ := osquery.NewClient(*socket, time.Second*time.Duration(*timeout))

		var index int64 = 0
		for {
			events := make([]map[string]string, 0)
			for i := 0; i < 100; i++ {
				events = append(events, map[string]string{
					"text":    "1234",
					"integer": strconv.FormatInt(index, 10),
					"big_int": "1.2345",
					"double":  "hello",
				})
				index++
			}
			client.StreamEvents("example_events", events)
			time.Sleep(time.Second * 2)
		}
	}()

	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

// ExampleEventsColumns returns the example events table columns.
func ExampleEventsColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("text"),
		table.IntegerColumn("integer"),
		table.BigIntColumn("big_int"),
		table.DoubleColumn("double"),
	}
}

// ExampleEventsGenerate is never called.
func ExampleEventsGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	return nil, nil
}
