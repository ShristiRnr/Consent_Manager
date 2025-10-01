-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS update_notification_preferences_modtime ON notification_preferences;
DROP FUNCTION IF EXISTS update_modified_column();
DROP TABLE IF EXISTS notification_preferences;
-- +goose StatementEnd
