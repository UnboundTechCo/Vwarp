package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"log/slog"
	"net/netip"
	"os"
	"path"
	"time"

	"github.com/adrg/xdg"
	"github.com/bepass-org/warp-plus/app"
	p "github.com/bepass-org/warp-plus/psiphon"
	"github.com/bepass-org/warp-plus/warp"
	"github.com/bepass-org/warp-plus/wiresocks"
	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffval"
)

type rootConfig struct {
	flags   *ff.FlagSet
	command *ff.Command

	verbose  bool
	v4       bool
	v6       bool
	bind     string
	endpoint string
	key      string
	dns      string
	gool     bool
	psiphon  bool
	country  string
	scan     bool
	rtt      time.Duration
	cacheDir string
	fwmark   uint32
	reserved string
	wgConf   string
	testUrl  string
	config   string
}

func newRootCmd() *rootConfig {
	var cfg rootConfig
	cfg.flags = ff.NewFlagSet(appName)
	cfg.flags.AddFlag(ff.FlagConfig{
		ShortName: 'v',
		LongName:  "verbose",
		Value:     ffval.NewValueDefault(&cfg.verbose, false),
		Usage:     "enable verbose logging",
		NoDefault: true,
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		ShortName: '4',
		Value:     ffval.NewValueDefault(&cfg.v4, false),
		Usage:     "only use IPv4 for random warp endpoint",
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		ShortName: '6',
		Value:     ffval.NewValueDefault(&cfg.v6, false),
		Usage:     "only use IPv6 for random warp endpoint",
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		ShortName: 'b',
		LongName:  "bind",
		Value:     ffval.NewValueDefault(&cfg.bind, "127.0.0.1:8086"),
		Usage:     "socks bind address",
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		ShortName: 'e',
		LongName:  "endpoint",
		Value:     ffval.NewValueDefault(&cfg.endpoint, ""),
		Usage:     "warp endpoint",
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		ShortName: 'k',
		LongName:  "key",
		Value:     ffval.NewValueDefault(&cfg.key, ""),
		Usage:     "warp key",
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		LongName: "dns",
		Value:    ffval.NewValueDefault(&cfg.dns, "1.1.1.1"),
		Usage:    "DNS address",
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		LongName: "gool",
		Value:    ffval.NewValueDefault(&cfg.gool, false),
		Usage:    "enable gool mode (warp in warp)",
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		LongName: "cfon",
		Value:    ffval.NewValueDefault(&cfg.psiphon, false),
		Usage:    "enable psiphon mode (must provide country as well)",
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		LongName: "country",
		Value:    ffval.NewEnum(&cfg.country, p.Countries...),
		Usage:    "psiphon country code",
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		LongName: "scan",
		Value:    ffval.NewValueDefault(&cfg.scan, false),
		Usage:    "enable warp scanning",
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		LongName: "rtt",
		Value:    ffval.NewValueDefault(&cfg.rtt, 1000*time.Millisecond),
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		LongName: "cache-dir",
		Value:    ffval.NewValueDefault(&cfg.cacheDir, ""),
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		LongName: "fwmark",
		Value:    ffval.NewValueDefault(&cfg.fwmark, 0x0),
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		LongName: "reserved",
		Value:    ffval.NewValueDefault(&cfg.reserved, ""),
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		LongName: "wgconf",
		Value:    ffval.NewValueDefault(&cfg.wgConf, ""),
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		LongName: "test-url",
		Value:    ffval.NewValueDefault(&cfg.testUrl, "http://connectivity.cloudflareclient.com/cdn-cgi/trace"),
	})
	cfg.flags.AddFlag(ff.FlagConfig{
		ShortName: 'c',
		LongName:  "config",
		Value:     ffval.NewValueDefault(&cfg.config, ""),
	})
	cfg.command = &ff.Command{
		Name:  appName,
		Flags: cfg.flags,
		Exec:  cfg.exec,
	}
	return &cfg
}

func (c *rootConfig) exec(ctx context.Context, args []string) error {
	l := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if c.verbose {
		l = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	if c.psiphon && c.gool {
		fatal(l, errors.New("can't use cfon and gool at the same time"))
	}

	if c.v4 && c.v6 {
		fatal(l, errors.New("can't force v4 and v6 at the same time"))
	}

	if !c.v4 && !c.v6 {
		c.v4, c.v6 = true, true
	}

	bindAddrPort, err := netip.ParseAddrPort(c.bind)
	if err != nil {
		fatal(l, fmt.Errorf("invalid bind address: %w", err))
	}

	dnsAddr, err := netip.ParseAddr(c.dns)
	if err != nil {
		fatal(l, fmt.Errorf("invalid DNS address: %w", err))
	}

	opts := app.WarpOptions{
		Bind:            bindAddrPort,
		Endpoint:        c.endpoint,
		License:         c.key,
		DnsAddr:         dnsAddr,
		Gool:            c.gool,
		FwMark:          c.fwmark,
		WireguardConfig: c.wgConf,
		Reserved:        c.reserved,
		TestURL:         c.testUrl,
	}

	switch {
	case c.cacheDir != "":
		opts.CacheDir = c.cacheDir
	case xdg.CacheHome != "":
		opts.CacheDir = path.Join(xdg.CacheHome, appName)
	case os.Getenv("HOME") != "":
		opts.CacheDir = path.Join(os.Getenv("HOME"), ".cache", appName)
	default:
		opts.CacheDir = "warp_plus_cache"
	}

	if c.psiphon {
		l.Info("psiphon mode enabled", "country", c.country)
		opts.Psiphon = &app.PsiphonOptions{Country: c.country}
	}

	if c.scan {
		l.Info("scanner mode enabled", "max-rtt", c.rtt)
		opts.Scan = &wiresocks.ScanOptions{V4: c.v4, V6: c.v6, MaxRTT: c.rtt}
	}

	// If the endpoint is not set, choose a random warp endpoint
	if opts.Endpoint == "" {
		addrPort, err := warp.RandomWarpEndpoint(c.v4, c.v6)
		if err != nil {
			fatal(l, err)
		}
		opts.Endpoint = addrPort.String()
	}

	 host := ""
    if ap, err := netip.ParseAddrPort(opts.Endpoint); err == nil {
        host = ap.Addr().String()
    } else if h, _, err2 := net.SplitHostPort(opts.Endpoint); err2 == nil {
        host = h
    } else {
        host = opts.Endpoint // already host without port
    }

    const preflightPort = 443     // send to :443 for the QUIC look (your capture)
    const initialSize   = 1200    // QUIC Initial UDP payloads are padded to ≥1200B (RFC 9000)

    const hexInitial = "0xc2000000011419fa4bb3599f336777de79f81ca9a8d80d91eeec000044c635cef024a885dcb66d1420a91a8c427e87d6cf8e08b563932f449412cddf77d3e2594ea1c7a183c238a89e9adb7ffa57c133e55c59bec101634db90afb83f75b19fe703179e26a31902324c73f82d9354e1ed8da39af610afcb27e6590a44341a0828e5a3d2f0e0f7b0945d7bf3402feea0ee6332e19bdf48ffc387a97227aa97b205a485d282cd66d1c384bafd63dc42f822c4df2109db5b5646c458236ddcc01ae1c493482128bc0830c9e1233f0027a0d262f92b49d9d8abd9a9e0341f6e1214761043c021d7aa8c464b9d865f5fbe234e49626e00712031703a3e23ef82975f014ee1e1dc428521dc23ce7c6c13663b19906240b3efe403cf30559d798871557e4e60e86c29ea4504ed4d9bb8b549d0e8acd6c334c39bb8fb42ede68fb2aadf00cfc8bcc12df03602bbd4fe701d64a39f7ced112951a83b1dbbe6cd696dd3f15985c1b9fef72fa8d0319708b633cc4681910843ce753fac596ed9945d8b839aeff8d3bf0449197bd0bb22ab8efd5d63eb4a95db8d3ffc796ed5bcf2f4a136a8a36c7a0c65270d511aebac733e61d414050088a1c3d868fb52bc7e57d3d9fd132d78b740a6ecdc6c24936e92c28672dbe00928d89b891865f885aeb4c4996d50c2bbbb7a99ab5de02ac89b3308e57bcecf13f2da0333d1420e18b66b4c23d625d836b538fc0c221d6bd7f566a31fa292b85be96041d8e0bfe655d5dc1afed23eb8f2b3446561bbee7644325cc98d31cea38b865bdcc507e48c6ebdc7553be7bd6ab963d5a14615c4b81da7081c127c791224853e2d19bafdc0d9f3f3a6de898d14abb0e2bc849917e0a599ed4a541268ad0e60ea4d147dc33d17fa82f22aa505ccb53803a31d10a7ca2fea0b290a52ee92c7bf4aab7cea4e3c07b1989364eed87a3c6ba65188cd349d37ce4eefde9ec43bab4b4dc79e03469c2ad6b902e28e0bbbbf696781ad4edf424ffb35ce0236d373629008f142d04b5e08a124237e03e3149f4cdde92d7fae581a1ac332e26b2c9c1a6bdec5b3a9c7a2a870f7a0c25fc6ce245e029b686e346c6d862ad8df6d9b62474fbc31dbb914711f78074d4441f4e6e9edca3c52315a5c0653856e23f681558d669f4a4e6915bcf42b56ce36cb7dd3983b0b1d6fdf0f8efddb68e7ca0ae9dd4570fe6978fbb524109f6ec957ca61f1767ef74eb803b0f16abd0087cf2d01bc1db1c01d97ac81b3196c934586963fe7cf2d310e0739621e8bd00dc23fded18576d8c8f285d7bb5f43b547af3c76235de8b6f757f817683b2151600b11721219212bf27558edd439e73fce951f61d582320e5f4d6c315c71129b719277fc144bbe8ded25ab6d29b6e189c9bd9b16538faf60cc2aab3c3bb81fc2213657f2dd0ceb9b3b871e1423d8d3e8cc008721ef03b28e0ee7bb66b8f2a2ac01ef88df1f21ed49bf1ce435df31ac34485936172567488812429c269b49ee9e3d99652b51a7a614b7c460bf0d2d64d8349ded7345bedab1ea0a766a8470b1242f38d09f7855a32db39516c2bd4bcc538c52fa3a90c8714d4b006a15d9c7a7d04919a1cab48da7cce0d5de1f9e5f8936cffe469132991c6eb84c5191d1bcf69f70c58d9a7b66846440a9f0eef25ee6ab62715b50ca7bef0bc3013d4b62e1639b5028bdf757454356e9326a4c76dabfb497d451a3a1d2dbd46ec283d255799f72dfe878ae25892e25a2542d3ca9018394d8ca35b53ccd94947a8"

    // Fire-and-forget (don’t fail startup if it drops)
    _ = warp.SendRawQUICInitial(ctx, host, preflightPort, hexInitial, initialSize)
    // tiny spacing (optional)
    //time.Sleep(100 * time.Millisecond)
	go func() {
		if err := app.RunWarp(ctx, l, opts); err != nil {
			fatal(l, err)
		}
	}()

	<-ctx.Done()

	return nil
}
