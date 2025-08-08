package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"consultrnr/consent-manager/internal/models"
	"consultrnr/consent-manager/internal/services"

	"github.com/google/uuid"
)

type VendorHandler struct {
	service services.VendorService
}

func NewVendorHandler(service services.VendorService) *VendorHandler {
	return &VendorHandler{service: service}
}

func (h *VendorHandler) CreateVendor(w http.ResponseWriter, r *http.Request) {
	var vendor models.Vendor
	if err := json.NewDecoder(r.Body).Decode(&vendor); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if vendor.Company == "" || vendor.Email == "" {
		writeError(w, http.StatusBadRequest, "company and email required")
		return
	}
	if err := h.service.CreateVendor(&vendor); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, vendor)
}

func (h *VendorHandler) UpdateVendor(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid vendor id")
		return
	}

	var updateData models.Vendor
	if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	vendor, err := h.service.UpdateVendor(id, updateData)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, vendor)
}

func (h *VendorHandler) DeleteVendor(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid vendor id")
		return
	}

	if err := h.service.DeleteVendor(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "vendor deleted"})
}

func (h *VendorHandler) GetVendorByID(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid vendor id")
		return
	}

	vendor, err := h.service.GetVendorByID(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "vendor not found")
		return
	}
	writeJSON(w, http.StatusOK, vendor)
}

func (h *VendorHandler) ListVendors(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 10
	}

	vendors, total, err := h.service.ListVendors(page, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total":   total,
		"page":    page,
		"limit":   limit,
		"vendors": vendors,
	})
}
