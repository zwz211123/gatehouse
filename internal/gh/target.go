package gh

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func sshPublic(p ssh.PublicKey) []byte { return ssh.MarshalAuthorizedKey(p) }
func (c *Core) DialTarget(user, account string) (*ssh.Client, error) {
	a, b, k, e := c.ownerAccount(user, account)
	if e != nil {
		return nil, e
	}
	raw, e := c.Store.Unseal(k.ID, k.Cipher)
	if e != nil {
		return nil, e
	}
	signer, e := ssh.ParsePrivateKey(raw)
	for i := range raw {
		raw[i] = 0
	}
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ips, e := net.DefaultResolver.LookupIPAddr(ctx, b.Host)
	if e != nil {
		return nil, e
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no target addresses")
	}
	for _, ip := range ips {
		if !b.AllowSpecial && specialIP(ip.IP) {
			return nil, fmt.Errorf("target address denied")
		}
	}
	cfg := &ssh.ClientConfig{User: a.Name, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: func(_ string, _ net.Addr, p ssh.PublicKey) error {
		for _, s := range b.HostKeys {
			known, _, _, _, e := ssh.ParseAuthorizedKey([]byte(s))
			if e == nil && equalHash(hash(string(known.Marshal())), hash(string(p.Marshal()))) {
				return nil
			}
		}
		return fmt.Errorf("host key is unverified or changed")
	}, Timeout: 10 * time.Second}
	var last error
	for _, ip := range ips {
		address := net.JoinHostPort(ip.IP.String(), fmt.Sprint(b.Port))
		conn, e := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", address)
		if e != nil {
			last = e
			continue
		}
		conn.SetDeadline(time.Now().Add(15 * time.Second))
		cc, ch, req, e := ssh.NewClientConn(conn, net.JoinHostPort(b.Host, fmt.Sprint(b.Port)), cfg)
		if e != nil {
			conn.Close()
			return nil, e
		}
		conn.SetDeadline(time.Time{})
		return ssh.NewClient(cc, ch, req), nil
	}
	return nil, last
}
func specialIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	return strings.HasPrefix(ip.String(), "169.254.") || ip.Equal(net.ParseIP("100.100.100.200")) || ip.Equal(net.ParseIP("fd00:ec2::254"))
}
