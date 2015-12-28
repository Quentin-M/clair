package pgsql

import (
	"database/sql"

	cerrors "github.com/coreos/clair/utils/errors"
)

// InsertKeyValue stores (or updates) a single key / value tuple.
func (pgSQL *pgSQL) InsertKeyValue(key, value string) (err error) {
	if key == "" || value == "" {
		log.Warning("could not insert a flag which has an empty name or value")
		return cerrors.NewBadRequestError("could not insert a flag which has an empty name or value")
	}

	// Upsert.
	//
	// Note: UPSERT works only on >= PostgreSQL 9.5 which is not yet supported by AWS RDS.
	//       The best solution is currently the use of http://dba.stackexchange.com/a/13477
	//       but the key/value storage doesn't need to be super-efficient and super-safe at the
	//       moment so we can just use a client-side solution with transactions, based on
	//       http://postgresql.org/docs/current/static/plpgsql-control-structures.html.
	// TODO(Quentin-M): Enable Upsert as soon as 9.5 is stable.
	//
	// _, err = pgSQL.sqBuilder.Insert("keyvalue").
	// 	Columns("key", "value").
	// 	Values(key, value).
	// 	Suffix("ON CONFLICT (key) DO UPDATE SET value = ?", value).
	// 	Exec()

	for {
		// First, try to update.
		r, err := pgSQL.Exec("UPDATE KeyValue SET value = $1 WHERE key = $2", value, key)
		if err != nil {
			return err
		}
		if n, _ := r.RowsAffected(); n > 0 {
			// Updated successfully.
			return nil
		}

		// Try to insert the key.
		// If someone else inserts the same key concurrently, we could get a unique-key violation error.
		_, err = pgSQL.Exec("INSERT INTO KeyValue(key, value) VALUES($1, $2)", key, value)
		if err != nil {
			if isErrUniqueViolation(err) {
				// Got unique constraint violation, retry.
				continue
			}
			return err
		}

		return nil
	}
}

// GetValue reads a single key / value tuple and returns an empty string if the key doesn't exist.
func (pgSQL *pgSQL) GetKeyValue(key string) (value string, err error) {
	err = pgSQL.QueryRow("SELECT value FROM KeyValue WHERE key = $1", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return
}
