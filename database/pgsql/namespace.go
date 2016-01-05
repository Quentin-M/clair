package pgsql

import "github.com/coreos/clair/database"

// TODO(Quentin-M): Caching. There shouldn't be a lot of namespaces and most of them are re-used
// really often. Don't do a round-trip for nothing if we know it's there.
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
