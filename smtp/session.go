package smtp

// http://www.rfc-editor.org/rfc/rfc5321.txt

import (
	"io"
	"log"
	"strings"

	"github.com/ian-kent/linkio"
	"github.com/mailhog/MailHog-Server/config"
	"github.com/mailhog/MailHog-Server/monkey"
	"github.com/mailhog/data"
	"github.com/mailhog/smtp"
	"github.com/mailhog/storage"
)

// Session represents a SMTP session using net.TCPConn
type Session struct {
	conn          io.ReadWriteCloser
	proto         *smtp.Protocol
	storage       storage.Storage
	messageChan   chan *data.Message
	remoteAddress string
	isTLS         bool
	line          string
	link          *linkio.Link
	blacklist     map[string]bool

	reader io.Reader
	writer io.Writer
	monkey monkey.ChaosMonkey
}

// Accept starts a new SMTP session using io.ReadWriteCloser
func Accept(remoteAddress string, conn io.ReadWriteCloser, cfg *config.Config) {
	defer conn.Close()

	proto := smtp.NewProtocol()
	proto.Hostname = cfg.Hostname
	var link *linkio.Link
	reader := io.Reader(conn)
	writer := io.Writer(conn)
	if cfg.Monkey != nil {
		linkSpeed := cfg.Monkey.LinkSpeed()
		if linkSpeed != nil {
			link = linkio.NewLink(*linkSpeed * linkio.BytePerSecond)
			reader = link.NewLinkReader(io.Reader(conn))
			writer = link.NewLinkWriter(io.Writer(conn))
		}
	}

	session := &Session{conn, proto, cfg.Storage, cfg.MessageChan, remoteAddress, false, "", link, cfg.Blacklist, reader, writer, cfg.Monkey}
	proto.LogHandler = session.logf
	proto.MessageReceivedHandler = session.acceptMessage
	proto.ValidateSenderHandler = session.validateSender
	proto.ValidateRecipientHandler = session.validateRecipient
	proto.ValidateAuthenticationHandler = session.validateAuthentication
	proto.GetAuthenticationMechanismsHandler = func() []string { return []string{"PLAIN"} }

	session.logf("Starting session")
	session.Write(proto.Start())
	for session.Read() == true {
		if cfg.Monkey != nil && cfg.Monkey.Disconnect != nil && cfg.Monkey.Disconnect() {
			session.conn.Close()
			break
		}
	}
	session.logf("Session ended")
}

func (c *Session) validateAuthentication(mechanism string, args ...string) (errorReply *smtp.Reply, ok bool) {
	if c.monkey != nil {
		ok := c.monkey.ValidAUTH(mechanism, args...)
		if !ok {
			// FIXME better error?
			return smtp.ReplyUnrecognisedCommand(), false
		}
	}
	return nil, true
}

func (c *Session) validateRecipient(to string) bool {
	if c.blacklist != nil && c.blacklist[to] {
		c.logf("Rejecting email to blacklisted address: %s", to)
		return false
	}
	if c.monkey != nil {
		ok := c.monkey.ValidRCPT(to)
		if !ok {
			return false
		}
	}
	return true
}

func (c *Session) validateSender(from string) bool {
	if c.blacklist != nil && c.blacklist[from] {
		c.logf("Rejecting email from blacklisted address: %s", from)
		return false
	}
	if c.monkey != nil {
		ok := c.monkey.ValidMAIL(from)
		if !ok {
			return false
		}
	}
	return true
}

func (c *Session) acceptMessage(msg *data.SMTPMessage) (id string, err error) {
	m := msg.Parse(c.proto.Hostname)
	c.logf("Storing message %s", m.ID)
	id, err = c.storage.Store(m)
	c.messageChan <- m
	return
}

func (c *Session) logf(message string, args ...interface{}) {
	message = strings.Join([]string{"[SMTP %s]", message}, " ")
	args = append([]interface{}{c.remoteAddress}, args...)
	log.Printf(message, args...)
}

// Read reads from the underlying net.TCPConn
func (c *Session) Read() bool {
	buf := make([]byte, 1024)
	n, err := c.reader.Read(buf)

	if n == 0 {
		c.logf("Connection closed by remote host\n")
		io.Closer(c.conn).Close() // not sure this is necessary?
		return false
	}

	if err != nil {
		c.logf("Error reading from socket: %s\n", err)
		return false
	}

	text := string(buf[0:n])
	logText := strings.Replace(text, "\n", "\\n", -1)
	logText = strings.Replace(logText, "\r", "\\r", -1)
	c.logf("Received %d bytes: '%s'\n", n, logText)

	c.line += text

	for strings.Contains(c.line, "\r\n") {
		line, reply := c.proto.Parse(c.line)
		c.line = line

		if reply != nil {
			c.Write(reply)
			if reply.Status == 221 {
				io.Closer(c.conn).Close()
				return false
			}
		}
	}

	return true
}

// Write writes a reply to the underlying net.TCPConn
func (c *Session) Write(reply *smtp.Reply) {
	lines := reply.Lines()
	for _, l := range lines {
		logText := strings.Replace(l, "\n", "\\n", -1)
		logText = strings.Replace(logText, "\r", "\\r", -1)
		c.logf("Sent %d bytes: '%s'", len(l), logText)
		c.writer.Write([]byte(l))
	}
}
