package tls_client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	"github.com/bogdanfinn/quic-go-utls"
	"github.com/bogdanfinn/quic-go-utls/http3"
	"github.com/bogdanfinn/tls-client/bandwidth"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
	"golang.org/x/net/proxy"
)

const defaultIdleConnectionTimeout = 90 * time.Second

var errProtocolNegotiated = errors.New("protocol negotiated")

type roundTripper struct {
	clientHelloId     tls.ClientHelloID
	certificatePinner CertificatePinner

	dialer proxy.ContextDialer

	bandwidthTracker bandwidth.BandwidthTracker

	clientSessionCache tls.ClientSessionCache

	badPinHandlerFunc BadPinHandlerFunc
	cachedConnections map[string]net.Conn
	cachedTransports  map[string]http.RoundTripper

	headerPriority      *http2.PriorityParam
	settings            map[http2.SettingID]uint32
	transportOptions    *TransportOptions
	serverNameOverwrite string
	priorities          []http2.Priority
	pseudoHeaderOrder   []string
	settingsOrder       []http2.SettingID
	sync.Mutex

	cachedTransportsLck sync.Mutex
	connectionFlow      uint32

	forceHttp1   bool
	disableHttp3 bool

	insecureSkipVerify          bool
	withRandomTlsExtensionOrder bool
	disableIPV6                 bool
	disableIPV4                 bool
}

func (rt *roundTripper) CloseIdleConnections() {
	rt.cachedTransportsLck.Lock()
	defer rt.cachedTransportsLck.Unlock()

	type closeIdler interface {
		CloseIdleConnections()
	}

	for _, transport := range rt.cachedTransports {
		if tr, ok := transport.(closeIdler); ok {
			tr.CloseIdleConnections()
		}
	}
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	addr := rt.getDialTLSAddr(req)

	rt.cachedTransportsLck.Lock()

	if _, ok := rt.cachedTransports[addr]; !ok {
		if err := rt.getTransport(req, addr); err != nil {
			rt.cachedTransportsLck.Unlock()

			if errors.Is(err, ErrBadPinDetected) && rt.badPinHandlerFunc != nil {
				rt.badPinHandlerFunc(req)
			}

			return nil, err
		}
	}

	t := rt.cachedTransports[addr]
	rt.cachedTransportsLck.Unlock()

	return t.RoundTrip(req)
}

func (rt *roundTripper) getTransport(req *http.Request, addr string) error {
	switch strings.ToLower(req.URL.Scheme) {
	case "http":
		rt.cachedTransports[addr] = rt.buildHttp1Transport()
		return nil
	case "https":
	default:
		return fmt.Errorf("invalid URL scheme: [%v]", req.URL.Scheme)
	}

	// 修复：首先尝试 HTTP/3 (QUIC/UDP)，而不是在 TCP 上协商
	// HTTP/3 使用 QUIC (UDP)，在 TCP 连接上无法协商出 "h3" 协议
	// 因此我们需要先尝试直接使用 HTTP/3 Transport
	// 注意：如果 HTTP/3 连接失败，RoundTrip 会返回错误，我们需要在 RoundTrip 层处理降级
	if !rt.disableHttp3 {
		// 尝试创建 HTTP/3 Transport (QUIC/UDP)
		h3Transport, err := rt.buildHttp3Transport(req, addr)
		if err == nil {
			// 类型断言为 *http3.Transport
			if h3T, ok := h3Transport.(*http3.Transport); ok {
				// 包装 HTTP/3 Transport 以支持自动降级
				rt.cachedTransports[addr] = &http3TransportWithFallback{
					h3Transport:  h3T,
					roundTripper: rt,
					addr:         addr,
				}
				return nil
			}
			// 如果不是 *http3.Transport，直接使用
			rt.cachedTransports[addr] = h3Transport
			return nil
		}
		// HTTP/3 创建失败，继续使用 TCP (HTTP/2 或 HTTP/1.1)
	}

	// 降级到 TCP (HTTP/2 或 HTTP/1.1)
	_, err := rt.dialTLS(req.Context(), "tcp", addr)
	switch err {
	case errProtocolNegotiated:
	case nil:
		// Should never happen.
		panic("dialTLS returned no error when determining cachedTransports")
	default:
		return err
	}

	return nil
}

func (rt *roundTripper) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	rt.Lock()
	defer rt.Unlock()

	// If we have the connection from when we determined the HTTPS
	// cachedTransports to use, return that.
	if conn := rt.cachedConnections[addr]; conn != nil {
		delete(rt.cachedConnections, addr)

		return conn, nil
	}

	if network == "tcp" && rt.disableIPV6 {
		network = "tcp4"
	}

	if network == "tcp" && rt.disableIPV4 {
		network = "tcp6"
	}

	rawConn, err := rt.dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	var host string
	if host, _, err = net.SplitHostPort(addr); err != nil {
		host = addr
	}

	if rt.serverNameOverwrite != "" {
		host = rt.serverNameOverwrite
	}

	tlsConfig := &tls.Config{ClientSessionCache: rt.clientSessionCache, ServerName: host, InsecureSkipVerify: rt.insecureSkipVerify, OmitEmptyPsk: true}
	if rt.transportOptions != nil {
		tlsConfig.RootCAs = rt.transportOptions.RootCAs
		tlsConfig.KeyLogWriter = rt.transportOptions.KeyLogWriter
	}

	rawConn = rt.bandwidthTracker.TrackConnection(ctx, rawConn)

	conn := tls.UClient(rawConn, tlsConfig, rt.clientHelloId, rt.withRandomTlsExtensionOrder, rt.forceHttp1, rt.disableHttp3)
	if err = conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()

		return nil, err
	}

	err = rt.certificatePinner.Pin(conn, host)

	if err != nil {
		return nil, err
	}

	// 检查是否已经有缓存的 transport
	// 如果有，说明是在已有的 transport 上创建新连接，直接返回连接
	// 注意：这个检查在创建 transport 之后，如果在 switch 中已经设置了 transport，
	// 这里会返回 conn, nil 而不是继续执行到返回 errProtocolNegotiated
	if rt.cachedTransports[addr] != nil {
		// 注意：这里返回 nil 是正确的行为，表示连接已建立，transport 已存在
		// 调用者应该检查 err == nil 的情况（这不应该在 getTransport 中发生）
		return conn, nil
	}

	// No http.Transport constructed yet, create one based on the results
	// of ALPN if no http1 is enforced.

	switch conn.ConnectionState().NegotiatedProtocol {
	case http2.NextProtoTLS:
		utlsConfig := &tls.Config{ClientSessionCache: rt.clientSessionCache, InsecureSkipVerify: rt.insecureSkipVerify, OmitEmptyPsk: true}
		if rt.transportOptions != nil {
			utlsConfig.RootCAs = rt.transportOptions.RootCAs
		}

		if rt.serverNameOverwrite != "" {
			utlsConfig.ServerName = rt.serverNameOverwrite
		}

		idleConnectionTimeout := defaultIdleConnectionTimeout

		if rt.transportOptions != nil && rt.transportOptions.IdleConnTimeout != nil {
			idleConnectionTimeout = *rt.transportOptions.IdleConnTimeout
		}

		t2 := http2.Transport{
			DialTLS:         rt.dialTLSHTTP2,
			TLSClientConfig: utlsConfig,
			ConnectionFlow:  rt.connectionFlow,
			HeaderPriority:  rt.headerPriority,
			IdleConnTimeout: idleConnectionTimeout,
		}

		if rt.transportOptions != nil {
			t2.DisableCompression = rt.transportOptions.DisableCompression

			t1 := t2.GetT1()
			if t1 != nil {
				t1.DisableKeepAlives = rt.transportOptions.DisableKeepAlives
				t1.DisableCompression = rt.transportOptions.DisableCompression
				t1.MaxIdleConns = rt.transportOptions.MaxIdleConns
				t1.MaxIdleConnsPerHost = rt.transportOptions.MaxIdleConnsPerHost
				t1.MaxConnsPerHost = rt.transportOptions.MaxConnsPerHost
				t1.MaxResponseHeaderBytes = rt.transportOptions.MaxResponseHeaderBytes
				t1.WriteBufferSize = rt.transportOptions.WriteBufferSize
				t1.ReadBufferSize = rt.transportOptions.ReadBufferSize
				t1.IdleConnTimeout = idleConnectionTimeout
			}
		}

		if rt.pseudoHeaderOrder == nil {
			t2.PseudoHeaderOrder = []string{}
		} else {
			t2.PseudoHeaderOrder = rt.pseudoHeaderOrder
		}

		if rt.settings == nil {
			// when we not provide a map of custom http2 settings
			t2.Settings = map[http2.SettingID]uint32{
				http2.SettingMaxConcurrentStreams: 1000,
				http2.SettingMaxFrameSize:         16384,
				http2.SettingInitialWindowSize:    6291456,
				http2.SettingHeaderTableSize:      65536,
			}

			keys := make([]http2.SettingID, len(t2.Settings))

			i := 0
			// attention: the order might be random here for default values!
			for k := range t2.Settings {
				keys[i] = k
				i++
			}

			t2.SettingsOrder = keys
		} else {
			// use custom http2 settings
			t2.Settings = rt.settings
			t2.SettingsOrder = rt.settingsOrder
		}

		t2.Priorities = rt.priorities

		t2.PushHandler = &http2.DefaultPushHandler{}
		rt.cachedTransports[addr] = &t2
	case http3.NextProtoH3:
		utlsConfig := &tls.Config{
			ClientSessionCache: rt.clientSessionCache,
			InsecureSkipVerify: rt.insecureSkipVerify,
			OmitEmptyPsk:       true,
		}
		if rt.transportOptions != nil {
			utlsConfig.RootCAs = rt.transportOptions.RootCAs
		}

		if rt.serverNameOverwrite != "" {
			utlsConfig.ServerName = rt.serverNameOverwrite
		}

		if rt.transportOptions != nil {
			utlsConfig.RootCAs = rt.transportOptions.RootCAs
		}

		if rt.serverNameOverwrite != "" {
			utlsConfig.ServerName = rt.serverNameOverwrite
		}

		t3 := http3.Transport{
			TLSClientConfig: utlsConfig,
		}

		// HTTP/3 不使用 HTTP/2 的设置
		// HTTP/3 的 AdditionalSettings 应该是 HTTP/3 特定的设置 ID，而不是 HTTP/2 的设置 ID
		// 如果设置 HTTP/2 的设置（如 SETTINGS_MAX_CONCURRENT_STREAMS, ID 4），会导致错误：
		// "H3_SETTINGS_ERROR: received HTTP/2 specific setting in HTTP/3 session"
		// 因此，我们不设置 AdditionalSettings，让 HTTP/3 Transport 使用默认设置
		// 如果将来需要自定义 HTTP/3 设置，应该使用 HTTP/3 特定的设置 ID
		// 注意：rt.settings 是 HTTP/2 的设置，不适用于 HTTP/3
		t3.AdditionalSettings = nil

		if rt.transportOptions != nil {
			t3.DisableCompression = rt.transportOptions.DisableCompression
			t3.MaxResponseHeaderBytes = rt.transportOptions.MaxResponseHeaderBytes
		}

		rt.cachedTransports[addr] = &t3
	default:
		rt.cachedTransports[addr] = rt.buildHttp1Transport()
	}

	// Stash the connection just established for use servicing the
	// actual request (should be near-immediate).
	rt.cachedConnections[addr] = conn

	return nil, errProtocolNegotiated
}

func (rt *roundTripper) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if network == "tcp" && rt.disableIPV6 {
		network = "tcp4"
	}
	return rt.dialer.DialContext(ctx, network, addr)
}

func (rt *roundTripper) buildHttp1Transport() *http.Transport {
	utlsConfig := &tls.Config{ClientSessionCache: rt.clientSessionCache, InsecureSkipVerify: rt.insecureSkipVerify, OmitEmptyPsk: true}
	if rt.transportOptions != nil {
		utlsConfig.RootCAs = rt.transportOptions.RootCAs
	}

	if rt.serverNameOverwrite != "" {
		utlsConfig.ServerName = rt.serverNameOverwrite
	}

	idleConnectionTimeout := defaultIdleConnectionTimeout

	if rt.transportOptions != nil && rt.transportOptions.IdleConnTimeout != nil {
		idleConnectionTimeout = *rt.transportOptions.IdleConnTimeout
	}

	t := &http.Transport{DialContext: rt.dial, DialTLSContext: rt.dialTLS, TLSClientConfig: utlsConfig, ConnectionFlow: rt.connectionFlow, IdleConnTimeout: idleConnectionTimeout}

	if rt.transportOptions != nil {
		t.DisableKeepAlives = rt.transportOptions.DisableKeepAlives
		t.DisableCompression = rt.transportOptions.DisableCompression
		t.MaxIdleConns = rt.transportOptions.MaxIdleConns
		t.MaxIdleConnsPerHost = rt.transportOptions.MaxIdleConnsPerHost
		t.MaxConnsPerHost = rt.transportOptions.MaxConnsPerHost
		t.MaxResponseHeaderBytes = rt.transportOptions.MaxResponseHeaderBytes
		t.WriteBufferSize = rt.transportOptions.WriteBufferSize
		t.ReadBufferSize = rt.transportOptions.ReadBufferSize
	}

	return t
}

// buildHttp3Transport 创建 HTTP/3 Transport (QUIC/UDP)
func (rt *roundTripper) buildHttp3Transport(req *http.Request, addr string) (http.RoundTripper, error) {
	utlsConfig := &tls.Config{
		ClientSessionCache: rt.clientSessionCache,
		InsecureSkipVerify: rt.insecureSkipVerify,
		OmitEmptyPsk:       true,
	}
	if rt.transportOptions != nil {
		utlsConfig.RootCAs = rt.transportOptions.RootCAs
		utlsConfig.KeyLogWriter = rt.transportOptions.KeyLogWriter
	}

	var host string
	var err error
	if host, _, err = net.SplitHostPort(addr); err != nil {
		host = addr
	}

	if rt.serverNameOverwrite != "" {
		utlsConfig.ServerName = rt.serverNameOverwrite
	} else {
		utlsConfig.ServerName = host
	}

	t3 := http3.Transport{
		TLSClientConfig: utlsConfig,
	}

	// 配置自定义 Dial 函数，支持直接 IP 访问和 UDP 缓冲区优化
	t3.Dial = func(ctx context.Context, dialAddr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		// 解析地址
		dialHost, dialPortStr, err := net.SplitHostPort(dialAddr)
		if err != nil {
			return nil, err
		}

		dialPort, err := net.LookupPort("udp", dialPortStr)
		if err != nil {
			return nil, err
		}

		// 创建 UDP 连接
		udpConn, err := net.ListenUDP("udp", nil)
		if err != nil {
			return nil, err
		}

		// 尝试增加 UDP 接收缓冲区大小（QUIC 需要较大的缓冲区）
		// 设置接收缓冲区为 8MB（如果系统允许）
		if err := udpConn.SetReadBuffer(8 * 1024 * 1024); err != nil {
			// 如果设置失败，尝试设置较小的值
			udpConn.SetReadBuffer(2 * 1024 * 1024)
		}
		if err := udpConn.SetWriteBuffer(8 * 1024 * 1024); err != nil {
			udpConn.SetWriteBuffer(2 * 1024 * 1024)
		}

		// 解析目标 UDP 地址
		udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(dialHost, strconv.Itoa(dialPort)))
		if err != nil {
			udpConn.Close()
			return nil, err
		}

		transport := &quic.Transport{Conn: udpConn}
		return transport.DialEarly(ctx, udpAddr, tlsCfg, cfg)
	}

	// HTTP/3 不使用 HTTP/2 的设置
	// HTTP/3 的 AdditionalSettings 应该是 HTTP/3 特定的设置 ID，而不是 HTTP/2 的设置 ID
	// 如果设置 HTTP/2 的设置（如 SETTINGS_MAX_CONCURRENT_STREAMS, ID 4），会导致错误：
	// "H3_SETTINGS_ERROR: received HTTP/2 specific setting in HTTP/3 session"
	// 因此，我们不设置 AdditionalSettings，让 HTTP/3 Transport 使用默认设置
	// 如果将来需要自定义 HTTP/3 设置，应该使用 HTTP/3 特定的设置 ID
	// 注意：rt.settings 是 HTTP/2 的设置，不适用于 HTTP/3
	t3.AdditionalSettings = nil

	if rt.transportOptions != nil {
		t3.DisableCompression = rt.transportOptions.DisableCompression
		t3.MaxResponseHeaderBytes = rt.transportOptions.MaxResponseHeaderBytes
	}

	return &t3, nil
}

// http3TransportWithFallback 包装 HTTP/3 Transport，支持失败时自动降级到 HTTP/2
type http3TransportWithFallback struct {
	h3Transport  *http3.Transport
	roundTripper *roundTripper
	addr         string
	fallbackOnce sync.Once
	fallback     http.RoundTripper
	fallbackErr  error
	mu           sync.RWMutex // 保护 fallback 和 fallbackErr
}

func (h *http3TransportWithFallback) RoundTrip(req *http.Request) (*http.Response, error) {
	// 尝试使用 HTTP/3
	// 注意：HTTP/3 Transport 在 RoundTrip 时会尝试建立 QUIC 连接
	resp, err := h.h3Transport.RoundTrip(req)
	if err == nil {
		// HTTP/3 成功
		return resp, nil
	}

	// HTTP/3 失败，记录错误（用于调试）
	errStr := err.Error()

	// 检查是否是 context 取消（不应该降级）
	if req.Context().Err() != nil {
		return nil, fmt.Errorf("HTTP/3 failed (context cancelled): %w", err)
	}

	// 检查是否是明确不应该降级的错误类型
	// 例如：上下文取消错误（不应该降级，应该直接返回）
	if req.Context().Err() != nil {
		return nil, fmt.Errorf("HTTP/3 failed (context cancelled): %w", err)
	}

	// 对于所有其他 HTTP/3 错误，采用保守策略：尝试降级到 HTTP/2/HTTP/1.1
	// 这样可以提高兼容性，因为有些错误可能是 QUIC/UDP 特有的，TCP 连接可能成功
	// 已知应该降级的错误包括：
	// - 超时错误 (timeout, no recent network activity, i/o timeout)
	// - 连接错误 (connection refused, connection reset, network is unreachable)
	// - QUIC/UDP 特定错误 (UDP, QUIC, receive buffer)
	// - HTTP/3 协议错误 (H3_SETTINGS_ERROR 等)
	// 
	// 对于未知错误，也尝试降级，让 HTTP/2 有机会成功

	// HTTP/3 失败且应该降级，降级到 HTTP/2 或 HTTP/1.1
	// 使用 sync.Once 确保只创建一次 fallback transport
	h.fallbackOnce.Do(func() {
		// 直接构建 TCP transport (HTTP/2 或 HTTP/1.1)
		// 不通过 getTransport，而是直接构建，避免缓存冲突

		ctx := req.Context()
		if ctx == nil {
			ctx = context.Background()
		}

		// 临时禁用 HTTP/3，强制使用 TCP
		originalDisableHttp3 := h.roundTripper.disableHttp3
		h.roundTripper.disableHttp3 = true
		defer func() {
			h.roundTripper.disableHttp3 = originalDisableHttp3
		}()

		// 需要先清理可能的缓存连接和缓存连接
		// dialTLS 会检查 cachedConnections，如果存在会直接返回，导致返回 nil
		h.roundTripper.Lock()
		delete(h.roundTripper.cachedConnections, h.addr)
		h.roundTripper.Unlock()

		// 调用 dialTLS 来创建 TCP transport
		// 注意：dialTLS 内部会检查 cachedTransports，如果存在会直接返回连接
		// 我们需要先删除缓存，确保创建新的 transport
		h.roundTripper.cachedTransportsLck.Lock()
		// 临时保存原缓存（用于恢复，如果需要）
		oldTransport := h.roundTripper.cachedTransports[h.addr]
		delete(h.roundTripper.cachedTransports, h.addr)
		h.roundTripper.cachedTransportsLck.Unlock()

		// 调用 dialTLS 创建 TCP transport
		// 注意：dialTLS 可能返回以下值：
		// 1. errProtocolNegotiated: transport 已创建并缓存（正常情况）
		// 2. nil: 如果 cachedConnections[addr] 存在，或者在 dialTLS 内部创建 transport 后检查发现已存在
		// 3. 其他错误: 连接失败
		_, dialErr := h.roundTripper.dialTLS(ctx, "tcp", h.addr)

		// 检查缓存中的 transport（无论 dialErr 是什么）
		h.roundTripper.cachedTransportsLck.Lock()
		if t, ok := h.roundTripper.cachedTransports[h.addr]; ok {
			// 确保不是我们的 HTTP/3 wrapper
			if _, ok := t.(*http3TransportWithFallback); !ok {
				// 找到了非 HTTP/3 的 transport（TCP transport），使用它作为 fallback
				h.fallback = t
			} else {
				// 仍然是 HTTP/3 wrapper，说明清理失败或并发问题
				// 恢复原缓存并使用 HTTP/1.1 transport 作为最后的 fallback
				h.roundTripper.cachedTransports[h.addr] = oldTransport
				h.fallback = h.roundTripper.buildHttp1Transport()
			}
		} else {
			// 没有 transport，根据 dialErr 决定
			if dialErr == errProtocolNegotiated {
				// 应该是这种情况，但没有 transport，说明有问题
				h.roundTripper.cachedTransports[h.addr] = oldTransport
				h.fallbackErr = fmt.Errorf("dialTLS returned errProtocolNegotiated but no transport was cached")
			} else if dialErr == nil {
				// dialTLS 返回 nil，但没有 transport，可能是并发问题
				// 使用 HTTP/1.1 transport 作为 fallback
				h.roundTripper.cachedTransports[h.addr] = oldTransport
				h.fallback = h.roundTripper.buildHttp1Transport()
			} else {
				// 连接失败，恢复缓存并使用 HTTP/1.1 transport 作为 fallback
				h.roundTripper.cachedTransports[h.addr] = oldTransport
				h.fallback = h.roundTripper.buildHttp1Transport()
			}
		}
		h.roundTripper.cachedTransportsLck.Unlock()
	})

	if h.fallbackErr != nil {
		return nil, fmt.Errorf("HTTP/3 failed: %v, fallback failed: %v", err, h.fallbackErr)
	}

	if h.fallback != nil {
		// 使用 fallback transport 重试请求
		return h.fallback.RoundTrip(req)
	}

	return nil, fmt.Errorf("HTTP/3 failed: %v, and no fallback transport available", err)
}

func (rt *roundTripper) dialTLSHTTP2(network, addr string, _ *tls.Config) (net.Conn, error) {
	return rt.dialTLS(context.Background(), network, addr)
}

func (rt *roundTripper) getDialTLSAddr(req *http.Request) string {
	host, port, err := net.SplitHostPort(req.URL.Host)
	if err == nil {
		return net.JoinHostPort(host, port)
	}

	return net.JoinHostPort(req.URL.Host, "443")
}

func newRoundTripper(clientProfile profiles.ClientProfile, transportOptions *TransportOptions, serverNameOverwrite string, insecureSkipVerify bool, withRandomTlsExtensionOrder bool, forceHttp1 bool, disableHttp3 bool, certificatePins map[string][]string, badPinHandlerFunc BadPinHandlerFunc, disableIPV6 bool, disableIPV4 bool, bandwidthTracker bandwidth.BandwidthTracker, dialer ...proxy.ContextDialer) (http.RoundTripper, error) {
	pinner, err := NewCertificatePinner(certificatePins)
	if err != nil {
		return nil, fmt.Errorf("can not instantiate certificate pinner: %w", err)
	}

	var clientSessionCache tls.ClientSessionCache

	withSessionResumption := supportsSessionResumption(clientProfile.GetClientHelloId())

	if withSessionResumption {
		clientSessionCache = tls.NewLRUClientSessionCache(32)
	}

	rt := &roundTripper{
		dialer:                      dialer[0],
		certificatePinner:           pinner,
		badPinHandlerFunc:           badPinHandlerFunc,
		transportOptions:            transportOptions,
		clientSessionCache:          clientSessionCache,
		serverNameOverwrite:         serverNameOverwrite,
		settings:                    clientProfile.GetSettings(),
		settingsOrder:               clientProfile.GetSettingsOrder(),
		priorities:                  clientProfile.GetPriorities(),
		headerPriority:              clientProfile.GetHeaderPriority(),
		pseudoHeaderOrder:           clientProfile.GetPseudoHeaderOrder(),
		insecureSkipVerify:          insecureSkipVerify,
		forceHttp1:                  forceHttp1,
		disableHttp3:                disableHttp3,
		withRandomTlsExtensionOrder: withRandomTlsExtensionOrder,
		connectionFlow:              clientProfile.GetConnectionFlow(),
		clientHelloId:               clientProfile.GetClientHelloId(),
		cachedTransports:            make(map[string]http.RoundTripper),
		cachedConnections:           make(map[string]net.Conn),
		disableIPV6:                 disableIPV6,
		disableIPV4:                 disableIPV4,
		bandwidthTracker:            bandwidthTracker,
	}

	if len(dialer) > 0 {
		rt.dialer = dialer[0]
	} else {
		rt.dialer = proxy.Direct
	}

	return rt, nil
}

func supportsSessionResumption(id tls.ClientHelloID) bool {
	spec, err := tls.UTLSIdToSpec(id)
	if err != nil {
		spec, err = id.ToSpec()

		if err != nil {
			return false
		}
	}

	for _, ext := range spec.Extensions {
		if _, ok := ext.(*tls.UtlsPreSharedKeyExtension); ok {
			return true
		}
	}

	return false
}
