package realtime

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// Conn represents ONE browser-tab websocket.
type Conn struct {
	ws   *websocket.Conn
	user uuid.UUID
	hub  *Hub
	out  chan []byte
}

// Send implements the realtime.Client interface (so Hub can call it).
func (c *Conn) Send(payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	select {
	case c.out <- b:
	default: // channel full – drop to keep 50 ms goal
	}
	return nil
}

func (c *Conn) UserID() uuid.UUID { return c.user }

// ----------------------------------------------------------
// private loops
// ----------------------------------------------------------

func (c *Conn) readLoop(markRead func(uuid.UUID)) {
	defer c.close()

	for {
		// Client messages are tiny; decode directly.
		var in struct {
			Type string    `json:"type"`
			ID   uuid.UUID `json:"id"`
		}
		if err := c.ws.ReadJSON(&in); err != nil {
			return // closed
		}

		if in.Type == "mark_read" {
			markRead(in.ID) // service call sitting in handler
			ack := map[string]any{"type": "read_ack", "id": in.ID}
			c.hub.Publish(c.user, ack)
		}
	}
}

func (c *Conn) writeLoop() {
	tick := time.NewTicker(25 * time.Second)
	defer tick.Stop()

	for {
		select {
		case msg, ok := <-c.out:
			if !ok {
				_ = c.ws.WriteMessage(websocket.CloseMessage, nil)
				return
			}
			_ = c.ws.WriteMessage(websocket.TextMessage, msg)

		case <-tick.C:
			if err := c.ws.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// ----------------------------------------------------------

func (c *Conn) close() {
	c.hub.unreg <- c
	close(c.out)
	_ = c.ws.Close()
}

// ------------------------------------------------------------------
// Helper – called from the HTTP upgrader
// ------------------------------------------------------------------

func NewConn(user uuid.UUID, ws *websocket.Conn, hub *Hub,
	markRead func(uuid.UUID)) *Conn {

	conn := &Conn{
		ws:   ws,
		user: user,
		hub:  hub,
		out:  make(chan []byte, 8),
	}
	hub.register <- conn

	go conn.writeLoop()
	go conn.readLoop(markRead)

	return conn
}
