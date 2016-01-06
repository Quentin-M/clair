package pgsql

import (
	"database/sql"

	"github.com/coreos/clair/database"
	cerrors "github.com/coreos/clair/utils/errors"
	"github.com/guregu/null/zero"
)

func (pgSQL *pgSQL) FindLayer(name string, withFeatures, withVulnerabilities bool) (database.Layer, error) {
	// Find the layer
	var layer database.Layer
	var parentName sql.NullString
	var namespaceName sql.NullString

	err := pgSQL.QueryRow(getQuery("s_layer"), name).
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
	var query string
	if idOnly {
		query = getQuery("s_layer_featureversion_id_only")
	} else {
		query = getQuery("s_layer_featureversion")
	}

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

	rows, err := pgSQL.Query(getQuery("s_featureversions_vulnerabilities"),
		buildInputArray(featureVersionIDs))
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

// InsertLayer insert a single layer in the database
//
// The Name and EngineVersion fields are required.
// The Parent, Namespace, Features are optional.
// However, please note that the Parent field, if provided, is expected to have been retrieved
// using FindLayer with its Features.
//
// The Name MUST be unique for two different layers.
//
// TODO
// If the Layer already exists, nothing is done, except if the provided engine
// version is higher than the existing one, in which case, the OS,
// InstalledPackagesNodes and RemovedPackagesNodes fields will be replaced.
//
// The layer should only contains the newly installed/removed packages
// There is no safeguard that prevents from marking a package as newly installed
// while it has already been installed in one of its parent.
func (pgSQL *pgSQL) InsertLayer(layer database.Layer) error {
	// Verify parameters
	if layer.Name == "" {
		log.Warning("could not insert a layer which has an empty Name")
		return cerrors.NewBadRequestError("could not insert a layer which has an empty Name")
	}

	// Get a potentially existing layer.
	existingLayer, err := pgSQL.FindLayer(layer.Name, true, false)
	if err != nil && err != cerrors.ErrNotFound {
		return err
	}
	isExisting := err == nil

	// Begin transaction.
	tx, err := pgSQL.Begin()
	if err != nil {
		tx.Rollback()
		return err
	}

	// Find or insert namespace if provided.
	var namespaceID zero.Int
	if layer.Namespace != nil {
		n, err := pgSQL.insertNamespace(*layer.Namespace)
		if err != nil {
			tx.Rollback()
			return err
		}
		namespaceID = zero.IntFrom(int64(n))
	}

	if isExisting {
		// Insert a new layer.
		var parentID zero.Int
		if layer.Parent != nil {
			if layer.Parent.ID == 0 {
				log.Warning("Parent is expected to be retrieved from database when inserting a layer.")
				return cerrors.NewBadRequestError("Parent is expected to be retrieved from database when inserting a layer.")
			}

			parentID = zero.IntFrom(int64(layer.Parent.ID))
		}

		err = tx.QueryRow(getQuery("i_layer"), layer.Name, layer.EngineVersion, parentID, namespaceID).
			Scan(&layer.ID)
		if err != nil {
			tx.Rollback()
			return err
		}
	} else {
		if existingLayer.EngineVersion >= layer.EngineVersion {
			// The layer exists and has an equal or higher engine verison, do nothing.
			return nil
		}

		// Update an existing layer.
		_, err = tx.Exec(getQuery("u_layer"), layer.ID, layer.EngineVersion, namespaceID)
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	// Update Layer_diff_FeatureVersion now.
	updateDiffFeatureVersions(tx, &layer, &existingLayer)

	// Commit transaction.
	err = tx.Commit()
	if err != nil {
		tx.Rollback()
		return err
	}

	return nil
}

func updateDiffFeatureVersions(tx *sql.Tx, layer, existingLayer *database.Layer) {
	// TODO

	if existingLayer != nil {
		// We are updating a layer, we need to diff the Features with the existing Layer.

	} else if layer.Parent == nil {
		// There is no parent, every Features are added.

	} else if layer.Parent != nil {
		// There is a parent, we need to diff the Features with it.

	}
}

func (pgSQL *pgSQL) DeleteLayer(name string) error {
	// TODO
	return nil
}
