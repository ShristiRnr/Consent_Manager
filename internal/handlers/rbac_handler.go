package handlers

import (
	"consultrnr/consent-manager/internal/middlewares"
	"consultrnr/consent-manager/internal/models"
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"gorm.io/gorm"
)

type RBACHandler struct {
	DB *gorm.DB
}

func NewRBACHandler(db *gorm.DB) *RBACHandler {
	return &RBACHandler{DB: db}
}

// --- Role Management ---

type RoleRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Permissions []uint `json:"permissionIds"`
}

func (h *RBACHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetFiduciaryAuthClaims(r.Context())
	tenantID := uuid.MustParse(claims.TenantID)

	var req RoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	var permissions []*models.Permission
	if len(req.Permissions) > 0 {
		if err := h.DB.Where("id IN ?", req.Permissions).Find(&permissions).Error; err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to find permissions")
			return
		}
	}

	role := models.Role{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Name:        req.Name,
		Description: req.Description,
		Permissions: permissions,
	}

	if err := h.DB.Create(&role).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create role")
		return
	}

	writeJSON(w, http.StatusCreated, role)
}

func (h *RBACHandler) ListRoles(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetFiduciaryAuthClaims(r.Context())
	tenantID := uuid.MustParse(claims.TenantID)

	var roles []models.Role
	if err := h.DB.Preload("Permissions").Where("tenant_id = ?", tenantID).Find(&roles).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list roles")
		return
	}

	writeJSON(w, http.StatusOK, roles)
}

func (h *RBACHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetFiduciaryAuthClaims(r.Context())
	tenantID := uuid.MustParse(claims.TenantID)
	roleID, _ := uuid.Parse(mux.Vars(r)["roleId"])

	var req RoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	var role models.Role
	if err := h.DB.Where("id = ? AND tenant_id = ?", roleID, tenantID).First(&role).Error; err != nil {
		writeError(w, http.StatusNotFound, "Role not found")
		return
	}

	var permissions []*models.Permission
	if len(req.Permissions) > 0 {
		h.DB.Where("id IN ?", req.Permissions).Find(&permissions)
	}

	role.Name = req.Name
	role.Description = req.Description
	if err := h.DB.Model(&role).Association("Permissions").Replace(permissions); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update role permissions")
		return
	}

	h.DB.Save(&role)
	writeJSON(w, http.StatusOK, role)
}

func (h *RBACHandler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetFiduciaryAuthClaims(r.Context())
	tenantID := uuid.MustParse(claims.TenantID)
	roleID, _ := uuid.Parse(mux.Vars(r)["roleId"])

	if err := h.DB.Where("id = ? AND tenant_id = ?", roleID, tenantID).Delete(&models.Role{}).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete role")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Permission Management ---

func (h *RBACHandler) ListPermissions(w http.ResponseWriter, r *http.Request) {
	var permissions []models.Permission
	if err := h.DB.Find(&permissions).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list permissions")
		return
	}
	writeJSON(w, http.StatusOK, permissions)
}

// --- User-Role Assignment ---

type AssignRolesRequest struct {
	RoleIDs []uuid.UUID `json:"roleIds"`
}

func (h *RBACHandler) AssignRolesToUser(w http.ResponseWriter, r *http.Request) {
	claims := middlewares.GetFiduciaryAuthClaims(r.Context())
	tenantID := uuid.MustParse(claims.TenantID)
	userID, _ := uuid.Parse(mux.Vars(r)["userId"])

	var req AssignRolesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	var user models.FiduciaryUser
	if err := h.DB.Where("id = ? AND tenant_id = ?", userID, tenantID).First(&user).Error; err != nil {
		writeError(w, http.StatusNotFound, "User not found")
		return
	}

	var roles []*models.Role
	if len(req.RoleIDs) > 0 {
		if err := h.DB.Where("id IN ? AND tenant_id = ?", req.RoleIDs, tenantID).Find(&roles).Error; err != nil {
			writeError(w, http.StatusBadRequest, "One or more role IDs are invalid for this tenant")
			return
		}
	}

	if err := h.DB.Model(&user).Association("Roles").Replace(roles); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to assign roles to user")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Roles updated successfully"})
}
