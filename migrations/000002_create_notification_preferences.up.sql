-- +goose Up
-- +goose StatementBegin
CREATE TABLE notification_preferences (
    user_id UUID PRIMARY KEY REFERENCES data_principals(id) ON DELETE CASCADE,
    on_new_grievance BOOLEAN NOT NULL DEFAULT true,
    on_grievance_update BOOLEAN NOT NULL DEFAULT true,
    on_consent_update BOOLEAN NOT NULL DEFAULT true,
    on_new_consent_request BOOLEAN NOT NULL DEFAULT true,
    on_data_subject_request BOOLEAN NOT NULL DEFAULT true,
    on_data_subject_request_update BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create a trigger to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_modified_column() 
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW; 
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_notification_preferences_modtime
BEFORE UPDATE ON notification_preferences
FOR EACH ROW EXECUTE FUNCTION update_modified_column();

-- +goose StatementEnd
