package preflightbind

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	mathrand "math/rand"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bepass-org/warp-plus/wireguard/conn"
	"github.com/bepass-org/warp-plus/wireguard/device"
)

var rng = mathrand.New(mathrand.NewSource(time.Now().UnixNano()))

// AmneziaConfig holds the Amnezia WireGuard obfuscation parameters
type AmneziaConfig struct {
	// I1-I5: Signature packets for protocol imitation
	I1 string // Main obfuscation packet (hex string)
	I2 string // Additional signature packet
	I3 string // Additional signature packet
	I4 string // Additional signature packet
	I5 string // Additional signature packet
	
	// S1, S2: Random prefixes for Init/Response packets (0-64 bytes)
	S1 int // Random prefix for Init packets
	S2 int // Random prefix for Response packets
	
	// Junk packet configuration
	Jc   int // Number of junk packets (0-10)
	Jmin int // Minimum junk packet size (bytes)
	Jmax int // Maximum junk packet size (bytes)
	
	// Enhanced timing parameters for junk packets
	JcAfterI1  int // Junk packets to send after I1 packet
	JcBeforeHS int // Junk packets to send before handshake
	JcAfterHS  int // Junk packets to send after handshake
	
	// Timing configuration
	JunkInterval    time.Duration // Interval between junk packets
	AllowZeroSize   bool          // Allow zero-size junk packets
	HandshakeDelay  time.Duration // Delay before actual handshake after I1
}

// Bind wraps a conn.Bind and fires QUIC-like preflight when WG sends a handshake initiation.
type Bind struct {
	inner         conn.Bind
	port443       int            // usually 443
	payload       []byte         // I1 bytes
	amneziaConfig *AmneziaConfig // Amnezia configuration
	mu            sync.Mutex
	lastSent      map[netip.Addr]time.Time // rate-limit per dst IP
	interval      time.Duration            // e.g., 1s to avoid duplicate bursts
}

func New(inner conn.Bind, hexPayload string, port int, minInterval time.Duration) (*Bind, error) {
	// hexPayload may start with "0x..."
	h := hexPayload
	if len(h) >= 2 && (h[:2] == "0x" || h[:2] == "0X") {
		h = h[2:]
	}
	p, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	return &Bind{
		inner:    inner,
		port443:  port,
		payload:  p,
		lastSent: make(map[netip.Addr]time.Time),
		interval: minInterval,
	}, nil
}

// NewWithAmnezia creates a new Bind with Amnezia configuration
func NewWithAmnezia(inner conn.Bind, amneziaConfig *AmneziaConfig, port int, minInterval time.Duration) (*Bind, error) {
	var payload []byte
	var err error
	
	if amneziaConfig != nil && amneziaConfig.I1 != "" {
		// Parse I1 using CPS format
		payload, err = parseCPSPacket(amneziaConfig.I1)
		if err != nil {
			return nil, fmt.Errorf("invalid I1 CPS format: %w", err)
		}
	}
	
	return &Bind{
		inner:         inner,
		port443:       port,
		payload:       payload,
		amneziaConfig: amneziaConfig,
		lastSent:      make(map[netip.Addr]time.Time),
		interval:      minInterval,
	}, nil
}

func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) { return b.inner.Open(port) }
func (b *Bind) Close() error                                        { return b.inner.Close() }
func (b *Bind) SetMark(m uint32) error                              { return b.inner.SetMark(m) }
func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error)       { return b.inner.ParseEndpoint(s) }
func (b *Bind) BatchSize() int                                      { return b.inner.BatchSize() }

// handshakeInitiation reports whether buf looks like a WG handshake initiation.
// Per spec: first byte == 1 (init), next 3 bytes are reserved = 0. Size is 148 for init.
// However, Cloudflare Warp uses reserved bytes, so we only check the first byte and size.
func handshakeInitiation(buf []byte) bool {
	if len(buf) < device.MessageInitiationSize {
		return false
	}
	// Check if it's a WireGuard handshake initiation (type 1) with correct size
	// We don't check the reserved bytes since Cloudflare uses custom values
	return buf[0] == byte(device.MessageInitiationType) && len(buf) >= device.MessageInitiationSize
}

// parseCPSPacket parses a Custom Protocol Signature packet format
}

// parseCPSPacket parses a Custom Protocol Signature packet format
// Format: <b hex_data><c><t><r length>
func parseCPSPacket(cps string) ([]byte, error) {
	if cps == "" {
		return nil, nil
	}
	
	var result []byte
	remaining := cps
	
	// Parse CPS tags using regex
	tagRegex := regexp.MustCompile(`<([btcr])\s*([^>]*)>`)
	matches := tagRegex.FindAllStringSubmatch(remaining, -1)
	
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		
		tagType := match[1]
		tagData := strings.TrimSpace(match[2])
		
		switch tagType {
		case "b": // Static bytes
			if tagData != "" {
				// Remove 0x prefix if present
				if strings.HasPrefix(tagData, "0x") || strings.HasPrefix(tagData, "0X") {
					tagData = tagData[2:]
				}
				// Remove spaces
				tagData = strings.ReplaceAll(tagData, " ", "")
				bytes, err := hex.DecodeString(tagData)
				if err != nil {
					return nil, fmt.Errorf("invalid hex data in <b> tag: %w", err)
				}
				result = append(result, bytes...)
			}
		case "c": // Counter (32-bit, network byte order)
			counter := uint32(time.Now().Unix() % 0xFFFFFFFF)
			counterBytes := []byte{
				byte(counter >> 24),
				byte(counter >> 16),
				byte(counter >> 8),
				byte(counter),
			}
			result = append(result, counterBytes...)
		case "t": // Timestamp (32-bit, network byte order)
			timestamp := uint32(time.Now().Unix())
			timestampBytes := []byte{
				byte(timestamp >> 24),
				byte(timestamp >> 16),
				byte(timestamp >> 8),
				byte(timestamp),
			}
			result = append(result, timestampBytes...)
		case "r": // Random bytes
			length := 0
			if tagData != "" {
				var err error
				length, err = strconv.Atoi(tagData)
				if err != nil {
					return nil, fmt.Errorf("invalid length in <r> tag: %w", err)
				}
				if length > 1000 {
					length = 1000 // Cap at 1000 bytes as per spec
				}
			}
			if length > 0 {
				randomBytes := make([]byte, length)
				_, err := rand.Read(randomBytes)
				if err != nil {
					return nil, fmt.Errorf("failed to generate random bytes: %w", err)
				}
				result = append(result, randomBytes...)
			}
		}
	}
	
	return result, nil
}

// generateJunkPacket creates a junk packet with specified size constraints
func (b *Bind) generateJunkPacket() []byte {
	if b.amneziaConfig == nil {
		return nil
	}
	
	minSize := b.amneziaConfig.Jmin
	maxSize := b.amneziaConfig.Jmax
	
	// Handle zero-size configuration - true 0-byte packets like Amnezia
	if minSize == 0 && maxSize == 0 {
		return []byte{} // Return true empty packet
	}
	
	// If Jmin is 0, we can generate zero-size packets
	if minSize == 0 {
		if maxSize == 0 {
			return []byte{} // True zero-byte packet
		}
		// Random size from 0 to maxSize (inclusive) - allows true 0-byte
		size := rng.Intn(maxSize + 1)
		if size == 0 {
			return []byte{} // True zero-byte packet
		}
		
		junk := make([]byte, size)
		_, err := rand.Read(junk)
		if err != nil {
			// Fallback to math/rand if crypto/rand fails
			for i := range junk {
				junk[i] = byte(rng.Intn(256))
			}
		}
		return junk
	}
	
	// Allow zero-size packets if explicitly configured and minSize > 0
	if b.amneziaConfig.AllowZeroSize && minSize > 0 {
		// 50% chance for zero-size packet when allowed (increased from 20%)
		if rng.Intn(2) == 0 {
			return []byte{} // True zero-byte packet
		}
	}
	
	if minSize < 0 {
		minSize = 0
	}
	if maxSize < minSize {
		maxSize = minSize
	}
	
	var size int
	if maxSize == minSize {
		size = minSize
	} else {
		size = minSize + rng.Intn(maxSize-minSize+1)
	}
	
	if size == 0 {
		return []byte{} // True zero-byte packet
	}
	
	junk := make([]byte, size)
	_, err := rand.Read(junk)
	if err != nil {
		// Fallback to math/rand if crypto/rand fails
		for i := range junk {
			junk[i] = byte(rng.Intn(256))
		}
	}
	return junk
}

// sendJunkPackets sends a series of junk packets synchronously to control exact count
func (b *Bind) sendJunkPackets(host string, count int, interval time.Duration) {
	if count <= 0 {
		return
	}
	
	// Send packets synchronously to ensure exact count
	for i := 0; i < count; i++ {
		junk := b.generateJunkPacket()
		
		// Send immediately without goroutine to control count
		b.sendUDPPacket(host, junk)
		
		// Wait interval between packets (except for last one)
		if i < count-1 && interval > 0 {
			time.Sleep(interval)
		}
	}
}

// sendUDPPacket sends a UDP packet - attempts true zero-byte for empty data
func (b *Bind) sendUDPPacket(host string, data []byte) {
	if len(data) == 0 {
		// Send true zero-byte UDP packet
		b.sendTrueZeroByteUDP(host)
		return
	}
	
	// Normal UDP packet with data
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, strconv.Itoa(b.port443)), 400*time.Millisecond)
	if err != nil {
		return
	}
	defer conn.Close()
	
	_ = conn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	_, _ = conn.Write(data)
}

// sendTrueZeroByteUDP sends true zero-byte UDP packets using standard Go methods
func (b *Bind) sendTrueZeroByteUDP(host string) {
	// Use standard Go UDP methods which work reliably for zero-byte packets
	b.sendStandardZeroByte(host)
}

// sendStandardZeroByte sends zero-byte UDP packets using standard Go UDP methods
func (b *Bind) sendStandardZeroByte(host string) {
	// Method 1: Direct UDP connection with empty byte slice
	if conn, err := net.DialTimeout("udp", net.JoinHostPort(host, strconv.Itoa(b.port443)), 200*time.Millisecond); err == nil {
		_ = conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		conn.Write([]byte{})
		conn.Close()
	}
	
	// Method 2: PacketConn interface for additional reliability
	if conn, err := net.ListenPacket("udp", ":0"); err == nil {
		defer conn.Close()
		if addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(b.port443))); err == nil {
			_ = conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
			conn.WriteTo([]byte{}, addr)
		}
	}
}

func (b *Bind) maybePreflight(ep conn.Endpoint, bufs [][]byte) {
	dst := ep.DstIP()
	var seenInit bool
	for _, buf := range bufs {
		if handshakeInitiation(buf) {
			seenInit = true
			break
		}
	}
	if !seenInit {
		return
	}
	
	now := time.Now()
	b.mu.Lock()
	last := b.lastSent[dst]
	if now.Sub(last) < b.interval {
		b.mu.Unlock()
		return
	}
	b.lastSent[dst] = now
	b.mu.Unlock()

	host := dst.String()
	
	// Execute Amnezia sequence BEFORE sending the actual handshake
	if b.amneziaConfig != nil {
		// Send I1 packet and critical junk packets SYNCHRONOUSLY before handshake
		b.executeMinimalPreHandshakeSequence(host)
	} else {
		// Fallback to simple preflight SYNCHRONOUSLY
		b.executeSimplePreflight(host)
	}
}

// executeSimplePreflight sends a simple preflight packet (original behavior)
func (b *Bind) executeSimplePreflight(host string) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, strconv.Itoa(b.port443)), 400*time.Millisecond)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	_, _ = conn.Write(b.payload)
}

// executeMinimalPreHandshakeSequence sends critical packets synchronously before handshake
func (b *Bind) executeMinimalPreHandshakeSequence(host string) {
	config := b.amneziaConfig
	if config == nil {
		return
	}
	
	// Step 1: Send I1 packet FIRST (most critical) - SYNCHRONOUSLY
	if config.I1 != "" && b.payload != nil {
		conn, err := net.DialTimeout("udp", net.JoinHostPort(host, strconv.Itoa(b.port443)), 200*time.Millisecond)
		if err == nil {
			_ = conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
			_, _ = conn.Write(b.payload)
			conn.Close()
		}
		// Small delay after I1 to ensure it goes first
		time.Sleep(5 * time.Millisecond)
	}
	
	// Step 2: Send I2-I5 and critical junk packets synchronously BEFORE handshake
	b.executeFastPreHandshakeSequence(host)
	
	// Step 3: Schedule remaining packets asynchronously AFTER handshake
	go b.executePostHandshakeSequence(host)
}

// executeFastPreHandshakeSequence sends I2-I5 and critical junk packets quickly and synchronously
func (b *Bind) executeFastPreHandshakeSequence(host string) {
	config := b.amneziaConfig
	if config == nil {
		return
	}
	
	// Use minimal delays to avoid blocking handshake too long
	var fastDelay time.Duration = 3 * time.Millisecond
	
	// Step 1: Send I2-I5 signature packets quickly (I1 already sent)
	signatures := []string{"", config.I2, config.I3, config.I4, config.I5} // Skip I1
	for i, sig := range signatures {
		if i == 0 || sig == "" {
			continue
		}
		
		packet, err := parseCPSPacket(sig)
		if err != nil || len(packet) == 0 {
			continue
		}
		
		// Send quickly with minimal timeout
		conn, err := net.DialTimeout("udp", net.JoinHostPort(host, strconv.Itoa(b.port443)), 100*time.Millisecond)
		if err == nil {
			_ = conn.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
			_, _ = conn.Write(packet)
			conn.Close()
		}
		
		// Minimal delay between signature packets
		time.Sleep(fastDelay)
	}
	
	// Step 2: Send junk packets AFTER signature packets (I1-I5 complete)
	if config.JcBeforeHS > 0 {
		// Small delay after signature packets
		time.Sleep(fastDelay)
		
		// Limit to max 3 packets to avoid blocking handshake too long
		criticalCount := config.JcBeforeHS
		if criticalCount > 3 {
			criticalCount = 3
		}
		b.sendJunkPackets(host, criticalCount, fastDelay)
	}
	
	// Small final delay to ensure all packets are sent before handshake
	time.Sleep(2 * time.Millisecond)
}

// executeSimplePreflightSync sends a simple preflight packet synchronously
func (b *Bind) executeSimplePreflightSync(host string) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, strconv.Itoa(b.port443)), 200*time.Millisecond)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	_, _ = conn.Write(b.payload)
}

// executePostHandshakeSequence executes the Amnezia sequence that happens AFTER the handshake
func (b *Bind) executePostHandshakeSequence(host string) {
	config := b.amneziaConfig
	if config == nil {
		return
	}
	
	// Default timing values if not set
	junkInterval := config.JunkInterval
	if junkInterval == 0 {
		junkInterval = 10 * time.Millisecond
	}
	
	// Send remaining junk packets that didn't go in fast sequence
	if config.JcBeforeHS > 3 {
		// Send the remaining JcBeforeHS packets that were limited in fast sequence
		remainingCount := config.JcBeforeHS - 3
		b.sendJunkPackets(host, remainingCount, junkInterval)
	}
	
	// Send general junk train after handshake (if configured)
	if config.Jc > 0 {
		time.Sleep(50 * time.Millisecond) // Small delay
		b.sendJunkPackets(host, config.Jc, junkInterval)
	}
	
	// Send junk packets that were "after I1" → now "after handshake request"
	if config.JcAfterI1 > 0 {
		time.Sleep(30 * time.Millisecond) // Small delay
		b.sendJunkPackets(host, config.JcAfterI1, junkInterval)
	}
	
	// Send junk packets after handshake initiation (if configured)
	if config.JcAfterHS > 0 {
		time.Sleep(50 * time.Millisecond) // Small additional delay
		b.sendJunkPackets(host, config.JcAfterHS, junkInterval)
	}
}

func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.maybePreflight(ep, bufs)
	
	// For Cloudflare Warp compatibility, don't apply S1/S2 prefixes
	// The obfuscation is achieved through junk packets and I1-I5 signature packets
	return b.inner.Send(bufs, ep)
}

// applyAmneziaPrefix adds S1/S2 random prefixes to WireGuard packets
// Note: Only apply prefixes to handshake packets, not data packets for Cloudflare compatibility
func (b *Bind) applyAmneziaPrefix(buf []byte) []byte {
	if b.amneziaConfig == nil || len(buf) == 0 {
		return buf
	}
	
	var prefixSize int
	
	// Only apply prefixes to handshake packets (types 1 and 2)
	// For Cloudflare Warp compatibility, don't modify data packets
	if len(buf) >= 1 {
		messageType := buf[0]
		switch messageType {
		case 1: // Init packet (handshake initiation)
			prefixSize = b.amneziaConfig.S1
		case 2: // Response packet (handshake response)
			prefixSize = b.amneziaConfig.S2
		default:
			// For data packets, don't add prefixes to maintain Cloudflare compatibility
			return buf
		}
	}
	
	// Cap at 64 bytes as per spec
	if prefixSize > 64 {
		prefixSize = 64
	}
	
	if prefixSize <= 0 {
		return buf
	}
	
	// Generate random prefix
	prefix := make([]byte, prefixSize)
	_, err := rand.Read(prefix)
	if err != nil {
		// Fallback to math/rand if crypto/rand fails
		for i := range prefix {
			prefix[i] = byte(rng.Intn(256))
		}
	}
	
	// Prepend prefix to the original packet
	result := make([]byte, len(prefix)+len(buf))
	copy(result, prefix)
	copy(result[len(prefix):], buf)
	
	return result
}
