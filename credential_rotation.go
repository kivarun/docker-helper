package main

import (
	"database/sql"
	"errors"
	"fmt"
	"sync"
)

// ErrCredentialRotationConflict reports that the credential row no longer
// matches the exact state the rotation prepared against. This is an expected
// concurrent-state outcome, not an internal failure.
var ErrCredentialRotationConflict = errors.New("credential rotation conflict")

// ErrCredentialRotationDelivery reports that the fully serialized one-time
// bearer response could not be written. The transaction is rolled back and
// the previously active bearer remains authoritative.
var ErrCredentialRotationDelivery = errors.New("credential rotation response delivery failed")

// ErrCredentialRotationCommitUnknown reports the deliberately ambiguous
// boundary where the response write succeeded but the subsequent database
// commit returned an error. The handler must not retry automatically because
// the client may already possess the replacement bearer.
var ErrCredentialRotationCommitUnknown = errors.New("credential rotation commit outcome unknown")

// SQLite has one writer at a time. Keep the complete response-delivery
// transaction under the same in-process serialization boundary so concurrent
// rotations become deterministic CAS conflicts instead of leaking backend
// busy/locking errors through the public API.
var credentialRotationMu sync.Mutex

// credentialRotationCommitFn is the commit seam for the DB-backed credential
// rotation protocol. Production uses sql.Tx.Commit; tests replace it only to
// exercise the post-delivery ambiguous boundary deterministically.
var credentialRotationCommitFn = func(tx *sql.Tx) error {
	return tx.Commit()
}

// credentialRotationBeforeTransactionGate is a deterministic test seam for
// concurrent rotations. Production leaves it nil.
var credentialRotationBeforeTransactionGate func()

// commitCredentialRotationAfterDelivery is the single transaction/delivery
// owner for DB-backed bearer rotation (Principal and Launcher credentials).
//
// The caller must generate the replacement bearer and fully serialize its
// response before entering this function. replace performs an exact CAS-style
// UPDATE inside the transaction. Only after that tentative replacement exists
// does deliver write the already serialized response. A failed delivery rolls
// the transaction back; a successful delivery is followed by exactly one
// commit attempt. A commit error after delivery is intentionally returned as
// ErrCredentialRotationCommitUnknown and is never retried here.
func commitCredentialRotationAfterDelivery(
	db *sql.DB,
	replace func(*sql.Tx) error,
	deliver func() error,
) error {
	if credentialRotationBeforeTransactionGate != nil {
		credentialRotationBeforeTransactionGate()
	}

	credentialRotationMu.Lock()
	defer credentialRotationMu.Unlock()

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("cannot begin credential rotation transaction: %w", err)
	}
	defer tx.Rollback()

	if err := replace(tx); err != nil {
		return err
	}

	if err := deliver(); err != nil {
		return fmt.Errorf("%w: %v", ErrCredentialRotationDelivery, err)
	}

	if err := credentialRotationCommitFn(tx); err != nil {
		return fmt.Errorf("%w: %v", ErrCredentialRotationCommitUnknown, err)
	}

	return nil
}
