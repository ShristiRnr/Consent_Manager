package repository

import (
	"strings"

	"consultrnr/consent-manager/internal/db"
	"consultrnr/consent-manager/internal/models"
	"github.com/google/uuid"
	"gorm.io/gorm/clause"
)


// Email/phone values are normalized before insert. Existing rows are not overwritten with nils.
func FindUser(email, phone *string) (*models.MasterUser, error) {
	// Normalize input
	if email != nil {
		*email = strings.ToLower(strings.TrimSpace(*email))
	}
	if phone != nil {
		*phone = strings.TrimSpace(*phone)
	}

	user := models.MasterUser{
		UserID: uuid.New(),
	}
	if email != nil {
		user.Email = *email
	}
	if phone != nil {
		user.Phone = *phone
	}

	conflict := clause.OnConflict{
		Columns:   []clause.Column{{Name: "email"}, {Name: "phone"}},
		DoNothing: email == nil && phone == nil,
		DoUpdates: clause.Assignments(map[string]interface{}{
			"email": gormExprPreferExisting("email", email),
			"phone": gormExprPreferExisting("phone", phone),
		}),
	}

	if err := db.MasterDB.Clauses(conflict).Create(&user).Error; err != nil {
		return nil, err
	}

	return &user, nil
}

// FindMasterUserByID retrieves a MasterUser by UUID.
func FindMasterUserByID(userID uuid.UUID) (*models.MasterUser, error) {
	var user models.MasterUser
	if err := db.MasterDB.Where("user_id = ?", userID).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// gormExprPreferExisting returns a GORM clause.Expr to retain existing DB values when incoming is nil.
func gormExprPreferExisting(col string, val *string) clause.Expr {
	if val != nil {
		return clause.Expr{SQL: "COALESCE(EXCLUDED." + col + ", master_users." + col + ")"}
	}
	return clause.Expr{SQL: "master_users." + col}
}
