package handlers

import (
	"net/http"
)

func TestFunction(w http.ResponseWriter, r *http.Request) {
	writeError(w, 400, "test error")
}
