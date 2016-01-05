package pgsql

import (
	"testing"

	"github.com/coreos/clair/database"
	"github.com/stretchr/testify/assert"
)

func TestInsertNamespace(t *testing.T) {
	datastore, err := OpenForTest("FindLayer", false)
	if err != nil {
		t.Error(err)
		return
	}
	defer datastore.Close()

	id1, err := datastore.insertNamespace(database.Namespace{Name: "test"})
	assert.Nil(t, err)
	id2, err := datastore.insertNamespace(database.Namespace{Name: "test"})
	assert.Nil(t, err)
	assert.Equal(t, id1, id2)
}
