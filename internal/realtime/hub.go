package realtime

import (
	"sync"

	"github.com/google/uuid"
)

// Hub multiplexes any number of tabs / devices per user.
type Hub struct {
	mu       sync.RWMutex
	clients  map[uuid.UUID]map[*Conn]struct{} // user → set of conns
	register chan *Conn
	unreg    chan *Conn
}

func NewHub() *Hub {
	h := &Hub{
		clients:  make(map[uuid.UUID]map[*Conn]struct{}),
		register: make(chan *Conn),
		unreg:    make(chan *Conn),
	}
	go h.run()
	return h
}

func (h *Hub) run() {
	for {
		select {
		case c := <-h.register:
			h.mu.Lock()
			set := h.clients[c.user]
			if set == nil {
				set = make(map[*Conn]struct{})
				h.clients[c.user] = set
			}
			set[c] = struct{}{}
			h.mu.Unlock()

		case c := <-h.unreg:
			h.mu.Lock()
			if set, ok := h.clients[c.user]; ok {
				delete(set, c)
				if len(set) == 0 {
					delete(h.clients, c.user)
				}
			}
			h.mu.Unlock()
		}
	}
}

// --------------------------------------------------------------------
// Fan-out –  ≤ 50 ms to every active tab
// --------------------------------------------------------------------

func (h *Hub) Publish(user uuid.UUID, payload any) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for c := range h.clients[user] {
		_ = c.Send(payload) // ignore slow / dead tabs
	}
}
