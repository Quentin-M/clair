package pgsql

import (
	"database/sql"

	"github.com/coreos/clair-sql-database/database"
	cerrors "github.com/coreos/clair/utils/errors"
)

func (pgSQL *pgSQL) FindLayer(name string, withFeatures, withVulnerabilities bool) (database.Layer, error) {
	// Find the layer
	var layer database.Layer
	var parentName sql.NullString
	var namespaceName sql.NullString

	err := pgSQL.QueryRow(`
    SELECT l.id, l.name, l.engineversion, p.name, n.name
    FROM Layer l
      LEFT JOIN Layer p ON l.parent_id = p.id
      LEFT JOIN Namespace n ON l.namespace_id = n.id
    WHERE l.name = $1;`, name).
		Scan(&layer.ID, &layer.Name, &layer.EngineVersion, &parentName, &namespaceName)

	if err == sql.ErrNoRows {
		return layer, cerrors.ErrNotFound
	}
	if err != nil {
		return layer, err
	}

	if parentName.Valid {
		layer.Parent = &database.Layer{Name: parentName.String}
	}
	if namespaceName.Valid {
		layer.Namespace = &database.Namespace{Name: namespaceName.String}
	}

	// Find its features
	if withFeatures || withVulnerabilities {
		featureVersions, err := pgSQL.getLayerFeatureVersions(layer.ID, !withFeatures)
		if err != nil {
			return layer, err
		}
		layer.Features = featureVersions

		if withVulnerabilities {
			// Load the vulnerabilities that affect the FeatureVersions.
			err := pgSQL.loadAffectedBy(layer.Features)
			if err != nil {
				return layer, err
			}
		}
	}

	return layer, nil
}

// getLayerFeatureVersions returns list of database.FeatureVersion that a database.Layer has.
// if idOnly is specified, the returned structs will only have their ID filled. Otherwise,
// it also gets their versions, feature's names, feature's namespace's names.
func (pgSQL *pgSQL) getLayerFeatureVersions(layerID int, idOnly bool) ([]database.FeatureVersion, error) {
	var featureVersions []database.FeatureVersion

	// Build query
	query := `
    WITH RECURSIVE layer_tree(id, parent_id, depth, path, cycle) AS(
      SELECT l.id, l.parent_id, 1, ARRAY[l.id], false
      FROM Layer l
      WHERE l.id = $1
    UNION ALL
      SELECT l.id, l.parent_id, lt.depth + 1, path || l.id, l.id = ANY(path)
      FROM Layer l, layer_tree lt
      WHERE l.id = lt.parent_id
    )

    SELECT ldf.featureversion_id, ldf.modification `
	if !idOnly {
		query = query + ", fn.id, fn.name, f.id, f.name, fv.id, fv.version "
	}
	query = query + `
    FROM Layer_diff_FeatureVersion ldf
    JOIN (
      SELECT row_number() over (ORDER BY depth DESC), id FROM layer_tree
    ) AS ltree (ordering, id) ON ldf.layer_id = ltree.id `
	if !idOnly {
		query = query + `
      , FeatureVersion fv, Feature f, Namespace fn
      WHERE ldf.featureversion_id = fv.id AND fv.feature_id = f.id AND f.namespace_id = fn.id `
	}
	query = query + `ORDER BY ltree.ordering`

	// Query
	rows, err := pgSQL.Query(query, layerID)
	if err != nil && err != sql.ErrNoRows {
		return featureVersions, err
	}
	defer rows.Close()

	// Scan query
	var modification string
	mapFeatureVersions := make(map[int]database.FeatureVersion)
	for rows.Next() {
		var featureVersion database.FeatureVersion

		if idOnly {
			err = rows.Scan(&featureVersion.ID, &modification)
			if err != nil {
				return featureVersions, err
			}
		} else {
			err = rows.Scan(&featureVersion.ID, &modification, &featureVersion.Feature.Namespace.ID,
				&featureVersion.Feature.Namespace.Name, &featureVersion.Feature.ID,
				&featureVersion.Feature.Name, &featureVersion.ID, &featureVersion.Version)
			if err != nil {
				return featureVersions, err
			}
		}

		// Do transitive closure
		switch modification {
		case "add":
			mapFeatureVersions[featureVersion.ID] = featureVersion
		case "del":
			delete(mapFeatureVersions, featureVersion.ID)
		default:
			log.Warningf("unknown Layer_diff_FeatureVersion's modification: %s", modification)
			return featureVersions, database.ErrInconsistent
		}
	}
	if err = rows.Err(); err != nil {
		return featureVersions, err
	}

	// Build result by converting our map to a slice
	for _, featureVersion := range mapFeatureVersions {
		featureVersions = append(featureVersions, featureVersion)
	}

	return featureVersions, nil
}

// loadAffectedBy returns the list of database.Vulnerability that affect the given
// FeatureVersion.
func (pgSQL *pgSQL) loadAffectedBy(featureVersions []database.FeatureVersion) error {
	if len(featureVersions) == 0 {
		return nil
	}

	// Construct list of FeatureVersion IDs, we will do a single query
	featureVersionIDs := make([]int, 0, len(featureVersions))
	for i := 0; i < len(featureVersions); i++ {
		featureVersionIDs = append(featureVersionIDs, featureVersions[i].ID)
	}

	rows, err := pgSQL.Query(`
    SELECT vafv.featureversion_id, v.id, v.name, v.description, v.link, v.severity, vn.name, vfif.version
    FROM Vulnerability_Affects_FeatureVersion vafv, Vulnerability v,
         Namespace vn, Vulnerability_FixedIn_Feature vfif
    WHERE vafv.featureversion_id = ANY($1::integer[])
          AND vafv.vulnerability_id = v.id
          AND vafv.fixedin_id = vfif.id
          AND v.namespace_id = vn.id`, buildInputArray(featureVersionIDs))
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	defer rows.Close()

	vulnerabilities := make(map[int][]database.Vulnerability, len(featureVersions))
	var featureversionID int
	for rows.Next() {
		var vulnerability database.Vulnerability
		err := rows.Scan(&featureversionID, &vulnerability.ID, &vulnerability.Name,
			&vulnerability.Description, &vulnerability.Link, &vulnerability.Severity,
			&vulnerability.Namespace.Name, &vulnerability.FixedBy)
		if err != nil {
			return err
		}
		vulnerabilities[featureversionID] = append(vulnerabilities[featureversionID], vulnerability)
	}
	if err = rows.Err(); err != nil {
		return err
	}

	// Assign vulnerabilities to every FeatureVersions
	for i := 0; i < len(featureVersions); i++ {
		featureVersions[i].AffectedBy = vulnerabilities[featureVersions[i].ID]
	}

	return nil
}
