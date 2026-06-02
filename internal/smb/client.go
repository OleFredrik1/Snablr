package smb

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hirochachacha/go-smb2"
)

const (
	defaultPort        = "445"
	defaultDialTimeout = 5 * time.Second
	defaultOpTimeout   = 30 * time.Second
	defaultMaxDepth    = 64
	defaultMaxReadSize = 4 * 1024 * 1024
)

var (
	ErrNotConnected     = errors.New("smb client is not connected")
	ErrFileTooLarge     = errors.New("remote file exceeds configured read limit")
	ErrOperationTimeout = errors.New("smb operation timed out")
)

type RemoteFile struct {
	Host       string
	Share      string
	Path       string
	Name       string
	Size       int64
	ModifiedAt time.Time
	IsDir      bool
	Extension  string
}

type ShareInfo struct {
	Name        string
	Description string
	Type        string
}

type SMBClient interface {
	Connect(host, user, pass string) error
	Close() error
	ListShares() ([]ShareInfo, error)
	WalkShare(share string, fn func(RemoteFile) error) error
	ReadFile(share, path string) ([]byte, error)
}

type AuthOptions struct {
	Method       string
	CCachePath   string
	Krb5ConfPath string
}

type Client struct {
	mu sync.Mutex

	host       string
	serverName string
	user       string
	password   string
	domain     string

	dialTimeout time.Duration
	opTimeout   time.Duration
	maxDepth    int
	maxReadSize int64

	conn    net.Conn
	session *smb2.Session
}

func NewClient() *Client {
	return &Client{
		dialTimeout: defaultDialTimeout,
		opTimeout:   defaultOpTimeout,
		maxDepth:    defaultMaxDepth,
		maxReadSize: defaultMaxReadSize,
	}
}

func (c *Client) SetMaxReadSize(limit int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maxReadSize = limit
}

func (c *Client) SetOperationTimeout(timeout time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.opTimeout = timeout
}

func (c *Client) Connect(host, user, pass string) error {
	return c.ConnectWithOptions(host, user, pass, AuthOptions{Method: AuthNTLM})
}

func (c *Client) ConnectWithOptions(host, user, pass string, opts AuthOptions) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.session != nil || c.conn != nil {
		_ = c.closeLocked()
	}

	serverName, dialAddr, err := splitHost(host)
	if err != nil {
		return err
	}

	authMethod := normalizeAuthMethod(opts.Method)
	if authMethod == "" {
		return fmt.Errorf("unsupported SMB auth method %q", opts.Method)
	}

	domain, username := splitUser(user)
	initiator, cleanup, err := newInitiator(authMethod, serverName, username, pass, domain, opts)
	if err != nil {
		return err
	}
	defer cleanup()

	conn, err := net.DialTimeout("tcp", dialAddr, c.dialTimeout)
	if err != nil {
		return fmt.Errorf("dial %s: %w", dialAddr, err)
	}
	connectGuard := newOperationGuard(conn, c.opTimeout)

	dialer := &smb2.Dialer{Initiator: initiator, Host: serverName}
	session, err := dialer.Dial(conn)
	err = connectGuard.finish(err)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("authenticate to %s: %w", serverName, err)
	}

	c.host = host
	c.serverName = serverName
	c.user = username
	c.password = pass
	c.domain = domain
	c.conn = conn
	c.session = session

	return nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeLocked()
}

func (c *Client) closeLocked() error {
	var errs []error

	if c.session != nil {
		guard := newOperationGuard(c.conn, c.opTimeout)
		err := guard.finish(c.session.Logoff())
		if err != nil && !isIgnorableCloseError(err) && !IsTimeoutError(err) {
			errs = append(errs, err)
		}
		c.session = nil
	}
	if c.conn != nil {
		if err := c.conn.Close(); err != nil && !isIgnorableCloseError(err) {
			errs = append(errs, err)
		}
		c.conn = nil
	}

	c.host = ""
	c.serverName = ""
	c.user = ""
	c.password = ""
	c.domain = ""

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func isIgnorableCloseError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}

	message := strings.ToLower(err.Error())
	return strings.Contains(message, "use of closed network connection") ||
		strings.Contains(message, "connection already closed")
}

func (c *Client) connectedSession() (*smb2.Session, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.session == nil {
		return nil, "", ErrNotConnected
	}
	return c.session, c.serverName, nil
}

func (c *Client) mountShare(share string) (*smb2.Share, error) {
	session, serverName, err := c.connectedSession()
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(share) == "" {
		return nil, fmt.Errorf("share cannot be empty")
	}

	mountPath := fmt.Sprintf(`\\%s\%s`, serverName, share)
	fs, err := session.Mount(mountPath)
	if err != nil {
		return nil, fmt.Errorf("mount %s: %w", mountPath, err)
	}
	return fs, nil
}

func (c *Client) mountShareWithDeadline(share string) (*smb2.Share, error) {
	guard := c.beginOperation()
	fs, err := c.mountShare(share)
	return fs, guard.finish(err)
}

func (c *Client) umountShareWithDeadline(fs *smb2.Share) {
	if fs == nil {
		return
	}
	guard := c.beginOperation()
	_ = guard.finish(fs.Umount())
}

func (c *Client) beginOperation() *operationGuard {
	c.mu.Lock()
	conn := c.conn
	timeout := c.opTimeout
	c.mu.Unlock()
	return newOperationGuard(conn, timeout)
}

type operationGuard struct {
	conn    net.Conn
	timeout time.Duration
	timer   *time.Timer
	done    chan struct{}
	expired atomic.Bool
}

func newOperationGuard(conn net.Conn, timeout time.Duration) *operationGuard {
	guard := &operationGuard{
		conn:    conn,
		timeout: timeout,
	}
	if conn == nil || timeout <= 0 {
		return guard
	}

	_ = conn.SetDeadline(time.Now().Add(timeout))
	guard.done = make(chan struct{})
	guard.timer = time.AfterFunc(timeout, func() {
		defer close(guard.done)
		guard.expired.Store(true)
		_ = conn.Close()
	})
	return guard
}

func (g *operationGuard) finish(err error) error {
	if g == nil {
		return err
	}

	if g.timer != nil {
		if !g.timer.Stop() && g.done != nil {
			<-g.done
		}
	}
	if g.conn != nil && !g.expired.Load() {
		_ = g.conn.SetDeadline(time.Time{})
	}
	if g.expired.Load() {
		if err == nil {
			return fmt.Errorf("%w after %s", ErrOperationTimeout, g.timeout)
		}
		return fmt.Errorf("%w after %s: %v", ErrOperationTimeout, g.timeout, err)
	}
	return err
}

func IsTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrOperationTimeout) {
		return true
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	message := strings.ToLower(err.Error())
	return strings.Contains(message, "i/o timeout") ||
		strings.Contains(message, "operation timed out")
}

func splitHost(host string) (serverName, dialAddr string, err error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", "", fmt.Errorf("host cannot be empty")
	}

	if parsedHost, parsedPort, splitErr := net.SplitHostPort(host); splitErr == nil {
		if parsedHost == "" {
			return "", "", fmt.Errorf("invalid host %q", host)
		}
		return parsedHost, net.JoinHostPort(parsedHost, parsedPort), nil
	}

	return host, net.JoinHostPort(host, defaultPort), nil
}

func splitUser(user string) (domain string, username string) {
	user = strings.TrimSpace(user)
	switch {
	case strings.Contains(user, `\`):
		parts := strings.SplitN(user, `\`, 2)
		return parts[0], parts[1]
	case strings.Contains(user, "@"):
		parts := strings.SplitN(user, "@", 2)
		return parts[1], parts[0]
	default:
		return "", user
	}
}
