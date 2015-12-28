package database

import "errors"

var (
	// ErrTransaction is an error that occurs when a database transaction fails.
	ErrTransaction = errors.New("database: transaction failed (concurrent modification?)")
	// ErrBackendException is an error that occurs when the database backend does
	// not work properly (ie. unreachable).
	ErrBackendException = errors.New("database: could not query backend")
	// ErrInconsistent is an error that occurs when a database consistency check
	// fails (ie. when an entity which is supposed to be unique is detected twice)
	ErrInconsistent = errors.New("database: inconsistent database")
	// ErrCantOpen is an error that occurs when the database could not be opened
	ErrCantOpen = errors.New("database: could not open database")
)

type Datastore interface {
	// Layer
	// InsertLayer(*Layer)
	FindLayer(name string, withFeatures, withVulnerabilities bool) (layer Layer, err error)
	// DeleteLayer(name string) error

	// Feature
	// InsertFeature([]*Feature) <<<--- TODO Dont need that!

	// Vulnerability
	// InsertVulnerabilities([]*Vulnerability)
	// DeleteVulnerability(id string)

	// Notifications
	// InsertNotifications([]*Notification) error
	// FindNotificationToSend() (*Notification, error)
	// CountNotificationsToSend() (int, error)
	// MarkNotificationAsSent(id string)

	// Key/Value
	InsertKeyValue(key, value string) error
	GetValue(key string) (string, error)

	// Lock
	// Lock(name string, duration time.Duration, owner string) (bool, time.Time)
	// Unlock(name, owner string)
	// LockInfo(name string) (string, time.Time, error)

	Close()
}
