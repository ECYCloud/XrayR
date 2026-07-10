package anytls

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/pires/go-proxyproto"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

// createProxyProtocolListener 在真实监听端口绑定一个 TCP 监听器，用于解析并剥离
// PROXY Protocol 头部、还原真实客户端地址后把连接直接注入 AnyTLS inbound。
//
// sing-box 自 1.6.0 起已移除内建的 Proxy Protocol 支持（ListenOptions.ProxyProtocol
// 现在只会返回 error），因此 AnyTLS inbound 不能像 xray-core 的 tcp/ws inbound 一样
// 直接通过监听器选项解析 PROXY 头：中转把 PROXY 头拼在 TLS ClientHello 前面转发给
// 节点后，sing-box 会把整段数据直接当成 TLS 记录解析，从而报
// "tls: first record does not look like a TLS handshake"。
// 这里借助 sing-box 官方支持的 adapter.TCPInjectableInbound 机制绕过其自身监听器：
// AnyTLS inbound 只监听一个外部不可达的回环端口（见 buildSingBox），真实端口由
// XrayR 自己监听、解析 PROXY 头后把连接连同真实来源地址一并交给 inbound 处理。
func createProxyProtocolListener(listenAddr netip.Addr, port uint16) (net.Listener, error) {
	tcpListener, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(netip.AddrPortFrom(listenAddr, port)))
	if err != nil {
		return nil, fmt.Errorf("listen proxy protocol frontend on %s:%d: %w", listenAddr, port, err)
	}

	// 默认 USE 策略：带 PROXY 头的连接解析并剥离后还原真实来源；不带头的连接
	// （如面板中转探活的空连接、未开启 PP 发送的中转）按原样放行。
	// 不能用 REQUIRE：探活连接不发数据即断开时 go-proxyproto 会把 EOF 转换为
	// ErrNoProxyProtocol（"proxy protocol signature not present"）并断掉连接。
	return &proxyproto.Listener{Listener: tcpListener}, nil
}

// startProxyProtocolFrontend 启动前置监听器的接受循环。必须在 box.Start() 成功后
// 调用，确保注入连接时路由与出站已就绪。
func (s *AnyTLSService) startProxyProtocolFrontend(ln net.Listener) error {
	inboundAny, ok := s.box.Inbound().Get(s.inboundTag)
	if !ok {
		return fmt.Errorf("anytls inbound %s not found", s.inboundTag)
	}
	injectable, ok := inboundAny.(adapter.TCPInjectableInbound)
	if !ok {
		return fmt.Errorf("anytls inbound %s does not support connection injection", s.inboundTag)
	}

	go s.acceptProxyProtocolConns(ln, injectable)
	return nil
}

func (s *AnyTLSService) acceptProxyProtocolConns(ln net.Listener, injectable adapter.TCPInjectableInbound) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.logger.Warnf("AnyTLS proxy protocol frontend accept error: %v", err)
			continue
		}
		go func() {
			var metadata adapter.InboundContext
			metadata.Inbound = s.inboundTag
			metadata.InboundType = "anytls"
			// RemoteAddr/LocalAddr 在 proxyproto.Conn 上会同步读取并剥离 PROXY 头，
			// 之后 conn 的后续 Read/Write 拿到的就是纯 TLS 数据。
			metadata.Source = M.SocksaddrFromNet(conn.RemoteAddr()).Unwrap()
			metadata.OriginDestination = M.SocksaddrFromNet(conn.LocalAddr()).Unwrap()
			injectable.NewConnectionEx(context.Background(), conn, metadata, nil)
		}()
	}
}
