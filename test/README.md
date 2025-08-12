# Testing

This directory contains all unit and integration tests for the Consent Manager server.

## Structure

- `unit/` - Unit tests for individual components
- `integration/` - Integration tests for API endpoints and services
- `fixtures/` - Test data and fixtures
- `helpers/` - Test helper functions and utilities

## Running Tests

```bash
go test ./test/...
```

## Test Database

Tests use a separate test database defined in `test_db_schema.sql` to avoid interfering with development or production data.
