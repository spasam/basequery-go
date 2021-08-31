package main

import (
	"context"
	"flag"
	"log"
	"time"

	osquery "github.com/Uptycs/basequery-go"
	"github.com/Uptycs/basequery-go/plugin/table"
)

var (
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
		"example_extension",
		*socket,
		serverTimeout,
		serverPingInterval,
		serverPromPort,
	)

	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}
	server.RegisterPlugin(table.NewPlugin("example_table", ExampleColumns(), ExampleGenerate))
	server.RegisterPlugin(table.NewPlugin("another_table", AnotherColumns(), AnotherGenerate))
	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

// ExampleColumns returns the example table columns.
func ExampleColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("text"),
		table.IntegerColumn("integer"),
		table.BigIntColumn("big_int"),
		table.DoubleColumn("double"),
	}
}

// AnotherColumns returns the another table columns.
func AnotherColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("text"),
		table.IntegerColumn("integer"),
		table.BigIntColumn("big_int"),
		table.DoubleColumn("double"),
	}
}

// ExampleGenerate is called when this table is invoked. It returns one row static data.
func ExampleGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	return []map[string]string{
		{
			"text":    "hello world",
			"integer": "123",
			"big_int": "-1234567890",
			"double":  "3.14159",
		},
	}, nil
}

// AnotherGenerate is called when this table is invoked. It returns two row static data.
func AnotherGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	return []map[string]string{
		{
			"text":    "hello",
			"integer": "1234",
			"big_int": "12345678900",
			"double":  "1.2345",
		},
		{
			"text":    "world",
			"integer": "-1234",
			"big_int": "-12345678900",
			"double":  "-1.2345",
		},
	}, nil
}
