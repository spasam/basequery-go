package osquery

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/apache/thrift/lib/go/thrift"

	"github.com/Uptycs/basequery-go/gen/osquery"
	"github.com/Uptycs/basequery-go/transport"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Plugin exposes the basequery Plugin interface.
type Plugin interface {
	// Name is the name used to refer to the plugin (eg. the name of the
	// table the plugin implements).
	Name() string
	// RegistryName is which "registry" the plugin should be added to.
	// Valid names are ["config", "logger", "table"].
	RegistryName() string
	// Routes returns the detailed information about the interface exposed
	// by the plugin. See the example plugins for samples.
	Routes() osquery.ExtensionPluginResponse
	// Ping implements a health check for the plugin. If the plugin is in a
	// healthy state, StatusOK should be returned.
	Ping() osquery.ExtensionStatus
	// Call requests the plugin to perform its defined behavior, returning
	// a response containing the result.
	Call(context.Context, osquery.ExtensionPluginRequest) osquery.ExtensionResponse
	// Shutdown alerts the plugin to stop.
	Shutdown()
}

const defaultTimeout = 1 * time.Second
const defaultPingInterval = 5 * time.Second

// ExtensionManagerServer is an implementation of the full ExtensionManager
// API. Plugins can register with an extension manager, which handles the
// communication with the osquery process.
type ExtensionManagerServer struct {
	name           string
	version        string
	sockPath       string
	serverClient   ExtensionManager
	registry       map[string](map[string]Plugin)
	promServer     *http.Server
	pluginCounter  *prometheus.CounterVec
	pluginGauge    *prometheus.GaugeVec
	pluginTime     *prometheus.HistogramVec
	server         thrift.TServer
	transport      thrift.TServerTransport
	timeout        time.Duration
	pingInterval   time.Duration // How often to ping osquery server
	prometheusPort uint16        // Expose prometheus metrics, if > 0
	mutex          sync.Mutex
	started        bool // Used to ensure tests wait until the server is actually started
}

// validRegistryNames contains the allowable RegistryName() values. If a plugin
// attempts to register with another value, the program will panic.
var validRegistryNames = map[string]bool{
	"table":       true,
	"logger":      true,
	"config":      true,
	"distributed": true,
}

// ServerOption is function for setting extension manager server options.
type ServerOption func(*ExtensionManagerServer)

// ServerVersion can be used to specify the basequery SDK version.
func ServerVersion(version string) ServerOption {
	return func(s *ExtensionManagerServer) {
		s.version = version
	}
}

// ServerTimeout sets timeout duration for thrift socket.
func ServerTimeout(timeout time.Duration) ServerOption {
	return func(s *ExtensionManagerServer) {
		s.timeout = timeout
	}
}

// ServerPingInterval can be used to configure health check ping interval/frequency.
func ServerPingInterval(interval time.Duration) ServerOption {
	return func(s *ExtensionManagerServer) {
		s.pingInterval = interval
	}
}

// ServerPrometheusPort is used to specify the port on which prometheus metrics will be exposed.
// By default this is disabled (0). A positive integer port value should be specified to enable it.
func ServerPrometheusPort(port uint16) ServerOption {
	return func(s *ExtensionManagerServer) {
		s.prometheusPort = port
	}
}

// NewExtensionManagerServer creates a new extension management server
// communicating with osquery over the socket at the provided path. If
// resolving the address or connecting to the socket fails, this function will
// error.
func NewExtensionManagerServer(name string, sockPath string, opts ...ServerOption) (*ExtensionManagerServer, error) {
	// Initialize nested registry maps
	registry := make(map[string](map[string]Plugin))
	for reg := range validRegistryNames {
		registry[reg] = make(map[string]Plugin)
	}

	manager := &ExtensionManagerServer{
		name:           name,
		sockPath:       sockPath,
		registry:       registry,
		timeout:        defaultTimeout,
		pingInterval:   defaultPingInterval,
		prometheusPort: 0,
	}

	for _, opt := range opts {
		opt(manager)
	}

	serverClient, err := NewClient(sockPath, manager.timeout)
	if err != nil {
		return nil, err
	}
	manager.serverClient = serverClient

	return manager, nil
}

// GetClient returns the extension manager client.
func (s *ExtensionManagerServer) GetClient() ExtensionManager {
	return s.serverClient
}

// RegisterPlugin adds one or more OsqueryPlugins to this extension manager.
func (s *ExtensionManagerServer) RegisterPlugin(plugins ...Plugin) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for _, plugin := range plugins {
		if !validRegistryNames[plugin.RegistryName()] {
			panic("invalid registry name: " + plugin.RegistryName())
		}
		s.registry[plugin.RegistryName()][plugin.Name()] = plugin
	}
}

func (s *ExtensionManagerServer) genRegistry() osquery.ExtensionRegistry {
	registry := osquery.ExtensionRegistry{}
	for regName := range s.registry {
		registry[regName] = osquery.ExtensionRouteTable{}
		for _, plugin := range s.registry[regName] {
			registry[regName][plugin.Name()] = plugin.Routes()
		}
	}
	return registry
}

// Start registers the extension plugins and begins listening on a unix socket
// for requests from the osquery process. All plugins should be registered with
// RegisterPlugin() before calling Start().
func (s *ExtensionManagerServer) Start() error {
	var server thrift.TServer
	err := func() error {
		s.mutex.Lock()
		defer s.mutex.Unlock()
		registry := s.genRegistry()

		stat, err := s.serverClient.RegisterExtension(
			&osquery.InternalExtensionInfo{
				Name:    s.name,
				Version: s.version,
			},
			registry,
		)

		if err != nil {
			return errors.Wrap(err, "registering extension")
		}
		if stat.Code != 0 {
			return errors.Errorf("status %d registering extension: %s", stat.Code, stat.Message)
		}

		listenPath := fmt.Sprintf("%s.%d", s.sockPath, stat.UUID)

		processor := osquery.NewExtensionProcessor(s)

		s.transport, err = transport.OpenServer(listenPath, s.timeout)
		if err != nil {
			return errors.Wrapf(err, "opening server socket (%s)", listenPath)
		}

		s.server = thrift.NewTSimpleServer2(processor, s.transport)
		server = s.server

		if s.prometheusPort > 0 {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())

			s.promServer = &http.Server{
				Addr:    ":" + strconv.Itoa(int(s.prometheusPort)),
				Handler: mux,
			}

			s.pluginCounter = promauto.NewCounterVec(prometheus.CounterOpts{
				Name: "plugin_calls",
				Help: "Number of calls to a plugin action",
			}, []string{"plugin_name", "plugin_action"})
			s.pluginGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
				Name: "plugin_results",
				Help: "Number of results returns by plugin action",
			}, []string{"plugin_name", "plugin_action"})
			s.pluginTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
				Name: "plugin_duration_seconds",
				Help: "Histogram for plugin action duration in seconds",
			}, []string{"plugin_name", "plugin_action"})
		}

		s.started = true

		return nil
	}()

	if err != nil {
		return err
	}

	if s.promServer != nil {
		go func() {
			s.promServer.ListenAndServe()
		}()
	}

	return server.Serve()
}

// Run starts the extension manager and runs until osquery calls for a shutdown
// or the osquery instance goes away.
func (s *ExtensionManagerServer) Run() error {
	errc := make(chan error)
	go func() {
		errc <- s.Start()
	}()

	// Watch for the osquery process going away. If so, initiate shutdown.
	go func() {
		for {
			time.Sleep(s.pingInterval)

			status, err := s.serverClient.Ping()
			if err != nil {
				errc <- errors.Wrap(err, "extension ping failed")
				break
			}
			if status.Code != 0 {
				errc <- errors.Errorf("ping returned status %d", status.Code)
				break
			}
		}
	}()

	err := <-errc
	if s.promServer != nil {
		// Ignore promtheus shutdown errors
		s.promServer.Shutdown(context.Background())
	}
	if err := s.Shutdown(context.Background()); err != nil {
		return err
	}
	return err
}

// Ping implements the basic health check.
func (s *ExtensionManagerServer) Ping(ctx context.Context) (*osquery.ExtensionStatus, error) {
	return &osquery.ExtensionStatus{Code: 0, Message: "OK"}, nil
}

// Call routes a call from the osquery process to the appropriate registered
// plugin.
func (s *ExtensionManagerServer) Call(ctx context.Context, registry string, item string, request osquery.ExtensionPluginRequest) (*osquery.ExtensionResponse, error) {
	subreg, ok := s.registry[registry]
	if !ok {
		return &osquery.ExtensionResponse{
			Status: &osquery.ExtensionStatus{
				Code:    1,
				Message: "Unknown registry: " + registry,
			},
		}, nil
	}

	plugin, ok := subreg[item]
	if !ok {
		return &osquery.ExtensionResponse{
			Status: &osquery.ExtensionStatus{
				Code:    1,
				Message: "Unknown registry item: " + item,
			},
		}, nil
	}

	if s.pluginCounter != nil {
		s.pluginCounter.WithLabelValues(item, request["action"]).Inc()
	}
	if s.pluginTime != nil {
		timer := prometheus.NewTimer(s.pluginTime.WithLabelValues(item, request["action"]))
		defer timer.ObserveDuration()
	}
	response := plugin.Call(context.Background(), request)
	if s.pluginGauge != nil {
		s.pluginGauge.WithLabelValues(item, request["action"]).Set(float64(len(response.Response)))
	}

	return &response, nil
}

// Shutdown stops the server and closes the listening socket.
func (s *ExtensionManagerServer) Shutdown(ctx context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.server != nil {
		server := s.server
		s.server = nil
		// Stop the server asynchronously so that the current request
		// can complete. Otherwise, this is vulnerable to deadlock if a
		// shutdown request is being processed when shutdown is
		// explicitly called.
		go func() {
			server.Stop()
		}()
	}

	return nil
}

// Useful for testing
func (s *ExtensionManagerServer) waitStarted() {
	for {
		s.mutex.Lock()
		started := s.started
		s.mutex.Unlock()
		if started {
			time.Sleep(10 * time.Millisecond)
			break
		}
	}
}
