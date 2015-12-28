package pgsql

import (
	"testing"

	"github.com/coreos/clair/utils/types"
	"github.com/stretchr/testify/assert"
)

func TestFindLayer(t *testing.T) {
	datastore, err := OpenForTest("FindLayer", true)
	if err != nil {
		t.Error(err)
		return
	}
	defer datastore.Close()

	// Layer-0: no parent, no namespace, no feature, no vulnerability
	layer, err := datastore.FindLayer("layer-0", false, false)
	if assert.Nil(t, err) && assert.NotNil(t, layer) {
		assert.Equal(t, "layer-0", layer.Name)
		assert.Nil(t, layer.Namespace)
		assert.Nil(t, layer.Parent)
		assert.Equal(t, 1, layer.EngineVersion)
		assert.Len(t, layer.Features, 0)
	}

	layer, err = datastore.FindLayer("layer-0", true, false)
	if assert.Nil(t, err) && assert.NotNil(t, layer) {
		assert.Len(t, layer.Features, 0)
	}

	// Layer-1: one parent, adds two features, one vulnerability
	layer, err = datastore.FindLayer("layer-1", false, false)
	if assert.Nil(t, err) && assert.NotNil(t, layer) {
		assert.Equal(t, layer.Name, "layer-1")
		assert.Equal(t, "debian:7", layer.Namespace.Name)
		if assert.NotNil(t, layer.Parent) {
			assert.Equal(t, "layer-0", layer.Parent.Name)
		}
		assert.Equal(t, 1, layer.EngineVersion)
		assert.Len(t, layer.Features, 0)
	}

	layer, err = datastore.FindLayer("layer-1", true, false)
	if assert.Nil(t, err) && assert.NotNil(t, layer) && assert.Len(t, layer.Features, 2) {
		for _, featureVersion := range layer.Features {
			assert.Equal(t, "debian:7", featureVersion.Feature.Namespace.Name)

			switch featureVersion.Feature.Name {
			case "wechat":
				assert.Equal(t, types.NewVersionUnsafe("0.5"), featureVersion.Version)
			case "openssl":
				assert.Equal(t, types.NewVersionUnsafe("1.0"), featureVersion.Version)
			default:
				t.Errorf("unexpected package %s for layer-1", featureVersion.Feature.Name)
			}
		}
	}

	layer, err = datastore.FindLayer("layer-1", true, true)
	if assert.Nil(t, err) && assert.NotNil(t, layer) && assert.Len(t, layer.Features, 2) {
		for _, featureVersion := range layer.Features {
			assert.Equal(t, "debian:7", featureVersion.Feature.Namespace.Name)

			switch featureVersion.Feature.Name {
			case "wechat":
				assert.Equal(t, types.NewVersionUnsafe("0.5"), featureVersion.Version)
			case "openssl":
				assert.Equal(t, types.NewVersionUnsafe("1.0"), featureVersion.Version)

				if assert.Len(t, featureVersion.AffectedBy, 1) {
					assert.Equal(t, "debian:7", featureVersion.AffectedBy[0].Namespace.Name)
					assert.Equal(t, "CVE-OPENSSL-1-DEB7", featureVersion.AffectedBy[0].Name)
					assert.Equal(t, types.High, featureVersion.AffectedBy[0].Severity)
					assert.Equal(t, "A vulnerability affecting OpenSSL < 2.0 on Debian 7.0", featureVersion.AffectedBy[0].Description)
					assert.Equal(t, "http://google.com/#q=CVE-OPENSSL-1-DEB7", featureVersion.AffectedBy[0].Link)
					assert.Equal(t, types.NewVersionUnsafe("2.0"), featureVersion.AffectedBy[0].FixedBy)
				}
			default:
				t.Errorf("unexpected package %s for layer-1", featureVersion.Feature.Name)
			}
		}
	}
}

// // TestInvalidLayers tries to insert invalid layers
// func TestInvalidLayers(t *testing.T) {
// 	Open(&config.DatabaseConfig{Type: "memstore"})
// 	defer Close()
//
// 	assert.Error(t, InsertLayer(&Layer{ID: ""})) // No ID
// }
//
// func TestLayerUpdate(t *testing.T) {
// 	Open(&config.DatabaseConfig{Type: "memstore"})
// 	defer Close()
//
// 	l1 := &Layer{ID: "l1", OS: "os1", InstalledPackagesNodes: []string{"p1", "p2"}, RemovedPackagesNodes: []string{"p3", "p4"}, EngineVersion: 1}
// 	if assert.Nil(t, InsertLayer(l1)) {
// 		// Do not update layer content if the engine versions are equals
// 		l1b := &Layer{ID: "l1", OS: "os2", InstalledPackagesNodes: []string{"p1"}, RemovedPackagesNodes: []string{""}, EngineVersion: 1}
// 		if assert.Nil(t, InsertLayer(l1b)) {
// 			fl1b, err := FindOneLayerByID(l1.ID, FieldLayerAll)
// 			if assert.Nil(t, err) && assert.NotNil(t, fl1b) {
// 				assert.True(t, layerEqual(l1, fl1b), "layer contents are not equal, expected %v, have %s", l1, fl1b)
// 			}
// 		}
//
// 		// Update the layer content with new data and a higher engine version
// 		l1c := &Layer{ID: "l1", OS: "os2", InstalledPackagesNodes: []string{"p1", "p5"}, RemovedPackagesNodes: []string{"p6", "p7"}, EngineVersion: 2}
// 		if assert.Nil(t, InsertLayer(l1c)) {
// 			fl1c, err := FindOneLayerByID(l1c.ID, FieldLayerAll)
// 			if assert.Nil(t, err) && assert.NotNil(t, fl1c) {
// 				assert.True(t, layerEqual(l1c, fl1c), "layer contents are not equal, expected %v, have %s", l1c, fl1c)
// 			}
// 		}
// 	}
// }
