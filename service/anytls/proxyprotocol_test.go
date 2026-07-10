package anytls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	singanytls "github.com/anytls/sing-anytls"
	"github.com/pires/go-proxyproto"
	boxlog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	log "github.com/sirupsen/logrus"

	"github.com/ECYCloud/XrayR/api"
	"github.com/ECYCloud/XrayR/common/mylego"
	"github.com/ECYCloud/XrayR/service/controller"
)

const (
	testUserKey = "test-user-uuid"
	testUserUID = 7
)

// writeSelfSignedCert 生成自签名证书写入临时目录，返回 cert/key 路径。
func writeSelfSignedCert(t *testing.T) (string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "anytls.test"},
		DNSNames:     []string{"anytls.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func freePort(t *testing.T) uint32 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("alloc port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return uint32(port)
}

// startEchoServer 启动一个回显 TCP 服务，返回其地址。
func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 4096)
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						conn.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// startTestService 构建并启动一个开启 Proxy Protocol 的 AnyTLS 节点服务。
func startTestService(t *testing.T) (*AnyTLSService, string) {
	t.Helper()

	certPath, keyPath := writeSelfSignedCert(t)
	port := freePort(t)

	s := &AnyTLSService{
		config: &controller.Config{
			ListenIP: "127.0.0.1",
			CertConfig: &mylego.CertConfig{
				CertMode: "file",
				CertFile: certPath,
				KeyFile:  keyPath,
			},
		},
		nodeInfo: &api.NodeInfo{
			NodeType:            "AnyTLS",
			NodeID:              1,
			Port:                port,
			EnableTLS:           true,
			AcceptProxyProtocol: true,
			AnyTLSConfig:        &api.AnyTLSConfig{},
		},
		logger:       log.NewEntry(log.StandardLogger()),
		inboundTag:   "AnyTLS_test",
		users:        map[string]userRecord{testUserKey: {UID: testUserUID}},
		traffic:      make(map[string]*userTraffic),
		onlineIPs:    make(map[string]map[string]struct{}),
		ipLastActive: make(map[string]map[string]time.Time),
	}
	s.authUsers = append(s.authUsers, option.AnyTLSUser{Name: testUserKey, Password: testUserKey})

	boxInstance, _, err := s.buildSingBox()
	if err != nil {
		t.Fatalf("buildSingBox: %v", err)
	}
	s.box = boxInstance
	t.Cleanup(func() { s.Close() })

	if err := s.box.Start(); err != nil {
		t.Fatalf("box start: %v", err)
	}
	if err := s.startProxyProtocolFrontend(s.frontListener); err != nil {
		t.Fatalf("start frontend: %v", err)
	}

	return s, fmt.Sprintf("127.0.0.1:%d", port)
}

// proxyRoundTrip 通过 AnyTLS 协议向 echo 服务发送数据并校验回显；回显成功后、
// 连接关闭前（connCounter.Close 会按设计清理在线 IP）校验真实来源 IP 已被记录。
// ppVersion: 0 表示不发送 PROXY 头，1/2 表示对应版本。
func proxyRoundTrip(t *testing.T, s *AnyTLSService, nodeAddr, echoAddr string, ppVersion byte, spoofedIP, wantIP string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dialOut := func(ctx context.Context) (net.Conn, error) {
		raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", nodeAddr)
		if err != nil {
			return nil, err
		}
		if ppVersion > 0 {
			header := proxyproto.HeaderProxyFromAddrs(ppVersion,
				&net.TCPAddr{IP: net.ParseIP(spoofedIP), Port: 5678},
				raw.RemoteAddr())
			if _, err := header.WriteTo(raw); err != nil {
				raw.Close()
				return nil, err
			}
		}
		tlsConn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, err
		}
		return tlsConn, nil
	}

	client, err := singanytls.NewClient(ctx, singanytls.ClientConfig{
		Password: testUserKey,
		DialOut:  dialOut,
		Logger:   boxlog.NewNOPFactory().NewLogger("test-client"),
	})
	if err != nil {
		t.Fatalf("anytls client: %v", err)
	}
	defer client.Close()

	conn, err := client.CreateProxy(ctx, M.ParseSocksaddr(echoAddr))
	if err != nil {
		t.Fatalf("create proxy: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello anytls over proxy protocol")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	got := make([]byte, len(payload))
	if _, err := readFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}

	assertOnlineIP(t, s, wantIP)
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// assertOnlineIP 校验指定 IP 已被记录进用户在线 IP 集合。
func assertOnlineIP(t *testing.T, s *AnyTLSService, wantIP string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.RLock()
		_, ok := s.onlineIPs[testUserKey][wantIP]
		s.mu.RUnlock()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			s.mu.RLock()
			defer s.mu.RUnlock()
			t.Fatalf("online IP %s not recorded, got %v", wantIP, s.onlineIPs[testUserKey])
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestProxyProtocolFrontend(t *testing.T) {
	s, nodeAddr := startTestService(t)
	echoAddr := startEchoServer(t)

	t.Run("WithProxyProtocolV2", func(t *testing.T) {
		proxyRoundTrip(t, s, nodeAddr, echoAddr, 2, "203.0.113.10", "203.0.113.10")
	})

	t.Run("WithProxyProtocolV1", func(t *testing.T) {
		proxyRoundTrip(t, s, nodeAddr, echoAddr, 1, "203.0.113.11", "203.0.113.11")
	})

	t.Run("WithoutProxyProtocol", func(t *testing.T) {
		proxyRoundTrip(t, s, nodeAddr, echoAddr, 0, "", "127.0.0.1")
	})

	// 模拟面板中转探活：建立 TCP 连接后不发送任何数据立即断开，
	// 前置监听器不能因此中断，后续正常连接必须不受影响。
	t.Run("EmptyProbeConnection", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			probe, err := net.Dial("tcp", nodeAddr)
			if err != nil {
				t.Fatalf("probe dial: %v", err)
			}
			probe.Close()
		}
		proxyRoundTrip(t, s, nodeAddr, echoAddr, 2, "203.0.113.12", "203.0.113.12")
	})
}
