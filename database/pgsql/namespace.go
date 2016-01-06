package pgsql

import "github.com/coreos/clair/database"

func (pgSQL *pgSQL) insertNamespace(namespace database.Namespace) (id int, err error) {
	if pgSQL.cache != nil {
		if id, found := pgSQL.cache.Get("namespace:" + namespace.Name); found {
			return id.(int), nil
		}
	}

	err = pgSQL.QueryRow(getQuery("soi_namespace"), namespace.Name).Scan(&id)

	if pgSQL.cache != nil {
		pgSQL.cache.Add("namespace:"+namespace.Name, id)
	}

	return
}
