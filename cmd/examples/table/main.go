package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"sync"
	"time"

	osquery "github.com/Uptycs/basequery-go"
	"github.com/Uptycs/basequery-go/plugin/table"
)

var (
	socket      = flag.String("socket", "", "Path to the extensions UNIX domain socket")
	timeout     = flag.Int("timeout", 3, "Seconds to wait for autoloaded extensions")
	interval    = flag.Int("interval", 3, "Seconds delay between connectivity checks")
	mutableData []map[string]string
	lock        sync.RWMutex
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

	mutableData = []map[string]string{
		{
			"i": "1234",
			"b": "12345678900",
			"d": "1.2345",
			"t": "hello",
		},
		{
			"i": "-1234",
			"b": "-12345678900",
			"d": "-1.2345",
			"t": "world",
		},
	}

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
	server.RegisterPlugin(table.NewMutablePlugin("mutable_table", MutableColumns(), MutableGenerate, MutableInsert, MutableUpdate, MutableDelete))
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

// ExampleGenerate is called when select is run on example table. It returns static one row data.
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

// MutableColumns returns the mutable table columns.
func MutableColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.IntegerColumn("i"),
		table.BigIntColumn("b"),
		table.DoubleColumn("d"),
		table.TextColumn("t"),
	}
}

// MutableGenerate is called when mutable table is queried. It returns cached data.
func MutableGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	lock.RLock()
	defer lock.RUnlock()
	return mutableData, nil
}

// MutableInsert is called when mutable table is inserted into
func MutableInsert(ctx context.Context, autoRowID bool, row []interface{}) ([]map[string]string, error) {
	id := fmt.Sprintf("%d", int(row[0].(float64)))
	lock.Lock()
	mutableData = append(mutableData, map[string]string{
		"i": id,
		"b": fmt.Sprintf("%v", row[1]),
		"d": fmt.Sprintf("%f", row[2]),
		"t": fmt.Sprintf("%s", row[3]),
	})
	lock.Unlock()

	return []map[string]string{{"id": id, "status": "success"}}, nil
}

// MutableUpdate is called when mutable tale is updated
func MutableUpdate(ctx context.Context, rowID int64, row []interface{}) error {
	id := fmt.Sprintf("%d", int(row[0].(float64)))
	lock.Lock()
	mutableData[rowID] = map[string]string{
		"i": id,
		"b": fmt.Sprintf("%v", row[1]),
		"d": fmt.Sprintf("%f", row[2]),
		"t": fmt.Sprintf("%s", row[3]),
	}
	lock.Unlock()

	return nil
}

// MutableDelete is called when mutable table rows are deleted
func MutableDelete(ctx context.Context, rowID int64) error {
	lock.Lock()
	mutableData = append(mutableData[:rowID], mutableData[rowID+1:]...)
	lock.Unlock()

	return nil
}
