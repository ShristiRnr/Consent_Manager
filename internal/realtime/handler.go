package realtime

import (
	"net/http"

	"consultrnr/consent-manager/pkg/log"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(*http.Request) bool { return true },
}

// Handler upgrades HTTP → WS, registers the connection with the Hub and
// wires the “mark-read” callback back into your NotificationService.
func Handler(
	hub *Hub,
	whoAmI func(*http.Request) (uuid.UUID, error),
	markRead func(userID, notifID uuid.UUID) error,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		uid, err := whoAmI(r)
		if err != nil {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}

		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Logger.Warn().Err(err).Msg("ws upgrade failed")
			return
		}

		// thin wrapper so Conn.readLoop only needs a 1-arg func
		mr := func(notifID uuid.UUID) {
			_ = markRead(uid, notifID)
		}

		NewConn(uid, ws, hub, mr) // goroutines start inside NewConn
	}
}
