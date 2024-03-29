package osquery

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/apache/thrift/lib/go/thrift"

	"github.com/Uptycs/basequery-go/gen/osquery"
	"github.com/Uptycs/basequery-go/plugin/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Verify that an error in server.Start will return an error instead of deadlock.
func TestNoDeadlockOnError(t *testing.T) {
	registry := make(map[string](map[string]Plugin))
	for reg := range validRegistryNames {
		registry[reg] = make(map[string]Plugin)
	}
	mut := sync.Mutex{}
	mock := &MockExtensionManager{
		RegisterExtensionFunc: func(info *osquery.InternalExtensionInfo, registry osquery.ExtensionRegistry) (*osquery.ExtensionStatus, error) {
			mut.Lock()
			defer mut.Unlock()
			return nil, errors.New("Boom")
		},
		PingFunc: func() (*osquery.ExtensionStatus, error) {
			return &osquery.ExtensionStatus{}, nil
		},
	}
	server := &ExtensionManagerServer{
		serverClient: mock,
		registry:     registry,
	}

	log := func(ctx context.Context, typ logger.LogType, logText string) error {
		fmt.Printf("%s: %s\n", typ, logText)
		return nil
	}
	server.RegisterPlugin(logger.NewPlugin("testLogger", log))

	err := server.Run()
	assert.Error(t, err)
	mut.Lock()
	defer mut.Unlock()
	assert.True(t, mock.RegisterExtensionFuncInvoked)
}

// Ensure that the extension server will shutdown and return if the osquery
// instance it is talking to stops responding to pings.
func TestShutdownWhenPingFails(t *testing.T) {
	registry := make(map[string](map[string]Plugin))
	for reg := range validRegistryNames {
		registry[reg] = make(map[string]Plugin)
	}
	mock := &MockExtensionManager{
		RegisterExtensionFunc: func(info *osquery.InternalExtensionInfo, registry osquery.ExtensionRegistry) (*osquery.ExtensionStatus, error) {
			return &osquery.ExtensionStatus{}, nil
		},
		PingFunc: func() (*osquery.ExtensionStatus, error) {
			// As if the socket was closed
			return nil, syscall.EPIPE
		},
	}
	server := &ExtensionManagerServer{
		serverClient: mock,
		registry:     registry,
	}

	err := server.Run()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "broken pipe")
}

// How many parallel tests to run (because sync issues do not occur on every
// run, this maximizes our chances of seeing any issue by quickly executing
// many runs of the test).
const parallelTestShutdownDeadlock = 20

func TestShutdownDeadlock(t *testing.T) {
	for i := 0; i < parallelTestShutdownDeadlock; i++ {
		t.Run("", func(t *testing.T) {
			t.Parallel()
			testShutdownDeadlock(t)
		})
	}
}
func testShutdownDeadlock(t *testing.T) {
	tempPath, err := ioutil.TempFile("", "")
	require.Nil(t, err)
	defer os.Remove(tempPath.Name())

	retUUID := osquery.ExtensionRouteUUID(0)
	mock := &MockExtensionManager{
		RegisterExtensionFunc: func(info *osquery.InternalExtensionInfo, registry osquery.ExtensionRegistry) (*osquery.ExtensionStatus, error) {
			return &osquery.ExtensionStatus{Code: 0, UUID: retUUID}, nil
		},
	}
	server := ExtensionManagerServer{serverClient: mock, sockPath: tempPath.Name()}

	wait := sync.WaitGroup{}

	wait.Add(1)
	go func() {
		err := server.Start()
		require.Nil(t, err)
		wait.Done()
	}()
	// Wait for server to be set up
	server.waitStarted()

	// Create a raw client to access the shutdown method that is not
	// usually exposed.
	listenPath := fmt.Sprintf("%s.%d", tempPath.Name(), retUUID)
	addr, err := net.ResolveUnixAddr("unix", listenPath)
	require.Nil(t, err)
	timeout := 500 * time.Millisecond
	trans := thrift.NewTSocketFromAddrConf(addr, &thrift.TConfiguration{
		ConnectTimeout: timeout,
		SocketTimeout:  timeout,
	})
	err = trans.Open()
	require.Nil(t, err)
	client := osquery.NewExtensionManagerClientFactory(trans,
		thrift.NewTBinaryProtocolFactoryConf(&thrift.TConfiguration{}))

	// Simultaneously call shutdown through a request from the client and
	// directly on the server object.
	wait.Add(1)
	go func() {
		defer wait.Done()
		client.Shutdown(context.Background())
	}()

	wait.Add(1)
	go func() {
		defer wait.Done()
		err = server.Shutdown(context.Background())
		require.Nil(t, err)
	}()

	// Track whether shutdown completed
	completed := make(chan struct{})
	go func() {
		wait.Wait()
		close(completed)
	}()

	// either indicate successful shutdown, or fatal the test because it
	// hung
	select {
	case <-completed:
		// Success. Do nothing.
	case <-time.After(5 * time.Second):
		t.Fatal("hung on shutdown")
	}
}

func TestShutdownBasic(t *testing.T) {
	tempPath, err := ioutil.TempFile("", "")
	require.Nil(t, err)
	defer os.Remove(tempPath.Name())

	retUUID := osquery.ExtensionRouteUUID(0)
	mock := &MockExtensionManager{
		RegisterExtensionFunc: func(info *osquery.InternalExtensionInfo, registry osquery.ExtensionRegistry) (*osquery.ExtensionStatus, error) {
			return &osquery.ExtensionStatus{Code: 0, UUID: retUUID}, nil
		},
	}
	server := ExtensionManagerServer{serverClient: mock, sockPath: tempPath.Name()}

	completed := make(chan struct{})
	go func() {
		err := server.Start()
		require.NoError(t, err)
		close(completed)
	}()

	server.waitStarted()
	err = server.Shutdown(context.Background())
	require.NoError(t, err)

	// Either indicate successful shutdown, or fatal the test because it
	// hung
	select {
	case <-completed:
		// Success. Do nothing.
	case <-time.After(5 * time.Second):
		t.Fatal("hung on shutdown")
	}
}
