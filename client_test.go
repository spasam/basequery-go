package osquery

import (
	"context"
	"errors"
	"testing"

	"github.com/Uptycs/basequery-go/gen/osquery"
	"github.com/Uptycs/basequery-go/mock"
	"github.com/stretchr/testify/assert"
)

func TestQueryRows(t *testing.T) {
	mock := &mock.ExtensionManager{}
	client := &ExtensionManagerClient{Client: mock}

	// Transport related error
	mock.QueryFunc = func(ctx context.Context, sql string) (*osquery.ExtensionResponse, error) {
		return nil, errors.New("Boom")
	}
	_, err := client.QueryRows("select 1")
	assert.NotNil(t, err)
	_, err = client.QueryRow("select 1")
	assert.NotNil(t, err)

	// Nil status
	mock.QueryFunc = func(ctx context.Context, sql string) (*osquery.ExtensionResponse, error) {
		return &osquery.ExtensionResponse{}, nil
	}
	_, err = client.QueryRows("select 1")
	assert.NotNil(t, err)
	_, err = client.QueryRow("select 1")
	assert.NotNil(t, err)

	// Query error
	mock.QueryFunc = func(ctx context.Context, sql string) (*osquery.ExtensionResponse, error) {
		return &osquery.ExtensionResponse{
			Status: &osquery.ExtensionStatus{Code: 1, Message: "bad query"},
		}, nil
	}
	_, err = client.QueryRows("select bad query")
	assert.NotNil(t, err)
	_, err = client.QueryRow("select bad query")
	assert.NotNil(t, err)

	// Good query (one row)
	expectedRows := []map[string]string{
		{"1": "1"},
	}
	mock.QueryFunc = func(ctx context.Context, sql string) (*osquery.ExtensionResponse, error) {
		return &osquery.ExtensionResponse{
			Status:   &osquery.ExtensionStatus{Code: 0, Message: "OK"},
			Response: expectedRows,
		}, nil
	}
	rows, err := client.QueryRows("select 1")
	assert.Nil(t, err)
	assert.Equal(t, expectedRows, rows)
	row, err := client.QueryRow("select 1")
	assert.Nil(t, err)
	assert.Equal(t, expectedRows[0], row)

	// Good query (multiple rows)
	expectedRows = []map[string]string{
		{"1": "1"},
		{"1": "2"},
	}
	mock.QueryFunc = func(ctx context.Context, sql string) (*osquery.ExtensionResponse, error) {
		return &osquery.ExtensionResponse{
			Status:   &osquery.ExtensionStatus{Code: 0, Message: "OK"},
			Response: expectedRows,
		}, nil
	}
	rows, err = client.QueryRows("select 1 union select 2")
	assert.Nil(t, err)
	assert.Equal(t, expectedRows, rows)
	_, err = client.QueryRow("select 1 union select 2")
	assert.NotNil(t, err)
}
