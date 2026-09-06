package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	routingObserverScopeStoreContractV1  = "routing-observer-scope-store.v1"
	routingIncidentLatchStoreContractV1  = "routing-incident-latch-store.v1"
	routingIncidentOutboxStoreContractV1 = "routing-incident-outbox-store.v1"
)

type RoutingManagedScopeStore interface {
	LoadScopes() ([]routingStoredScope, error)
	PutScope(routingStoredScope) error
	DeleteScope(string) error
}

type RoutingIncidentStore interface {
	LoadLatches() ([]routingIncidentLatch, error)
	LoadOutbox() ([]routingIncidentOutboxItem, error)
	PutLatch(routingIncidentLatch) error
	DeleteLatch(string) error
	PutOutbox(routingIncidentOutboxItem) error
	DeleteOutbox(string) error
}

type routingStoredScope struct {
	OperationID  string              `json:"operation_id"`
	Scope        RoutingManagedScope `json:"scope"`
	ScopeHash    string              `json:"scope_hash"`
	PolicyHash   string              `json:"policy_hash"`
	ReadbackHash string              `json:"readback_hash"`
	StoredAt     time.Time           `json:"stored_at"`
}

type routingIncidentLatchState string

const (
	routingIncidentLatchOpened   routingIncidentLatchState = "opened"
	routingIncidentLatchAdmitted routingIncidentLatchState = "admitted"
	routingIncidentLatchConflict routingIncidentLatchState = "conflict"
)

type routingIncidentLatch struct {
	IncidentID     string                    `json:"incident_id"`
	IdempotencyKey string                    `json:"idempotency_key"`
	PayloadHash    string                    `json:"payload_hash"`
	ScopeKey       string                    `json:"scope_key"`
	ScopeHash      string                    `json:"scope_hash"`
	RouteVersion   int64                     `json:"route_version"`
	PolicyHash     string                    `json:"policy_hash"`
	RuleID         string                    `json:"rule_id"`
	State          routingIncidentLatchState `json:"state"`
	OpenedAt       time.Time                 `json:"opened_at"`
	AcknowledgedAt *time.Time                `json:"acknowledged_at,omitempty"`
	DuplicateCount uint64                    `json:"duplicate_count"`
	ConflictCount  uint64                    `json:"conflict_count"`
}

type routingIncidentOutboxItem struct {
	IncidentID        string          `json:"incident_id"`
	IdempotencyKey    string          `json:"idempotency_key"`
	PayloadHash       string          `json:"payload_hash"`
	ScopeKey          string          `json:"scope_key"`
	ScopeHash         string          `json:"scope_hash"`
	RouteVersion      int64           `json:"route_version"`
	PolicyHash        string          `json:"policy_hash"`
	RuleID            string          `json:"rule_id"`
	Body              json.RawMessage `json:"body"`
	CreatedAt         time.Time       `json:"created_at"`
	AttemptCount      int             `json:"attempt_count"`
	NextAttemptAt     time.Time       `json:"next_attempt_at"`
	LastFailureReason string          `json:"last_failure_reason,omitempty"`
}

type routingScopeEnvelope struct {
	ContractVersion string             `json:"contract_version"`
	Item            routingStoredScope `json:"item"`
}

type routingLatchEnvelope struct {
	ContractVersion string               `json:"contract_version"`
	Item            routingIncidentLatch `json:"item"`
}

type routingOutboxEnvelope struct {
	ContractVersion string                    `json:"contract_version"`
	Item            routingIncidentOutboxItem `json:"item"`
}

type routingObserverFileStore struct {
	rootDir         string
	scopesDir       string
	latchesDir      string
	outboxDir       string
	atomicWriteHook func(string) error
}

func newRoutingObserverFileStore(dataDir string) (*routingObserverFileStore, error) {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return nil, errors.New("routing observer data directory is empty")
	}
	root := filepath.Join(dataDir, "routing-observer-v1")
	store := &routingObserverFileStore{
		rootDir:    root,
		scopesDir:  filepath.Join(root, "scopes"),
		latchesDir: filepath.Join(root, "latches"),
		outboxDir:  filepath.Join(root, "outbox"),
	}
	for _, directory := range []string{store.rootDir, store.scopesDir, store.latchesDir, store.outboxDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, fmt.Errorf("create routing observer store: %w", err)
		}
	}
	return store, nil
}

func (s *routingObserverFileStore) LoadScopes() ([]routingStoredScope, error) {
	var envelopes []routingScopeEnvelope
	if err := s.loadDirectory(s.scopesDir, &envelopes); err != nil {
		return nil, err
	}
	items := make([]routingStoredScope, 0, len(envelopes))
	for _, envelope := range envelopes {
		if envelope.ContractVersion != routingObserverScopeStoreContractV1 {
			return nil, errors.New("routing observer scope store contract is unsupported")
		}
		items = append(items, envelope.Item)
	}
	return items, nil
}

func (s *routingObserverFileStore) LoadLatches() ([]routingIncidentLatch, error) {
	var envelopes []routingLatchEnvelope
	if err := s.loadDirectory(s.latchesDir, &envelopes); err != nil {
		return nil, err
	}
	items := make([]routingIncidentLatch, 0, len(envelopes))
	for _, envelope := range envelopes {
		if envelope.ContractVersion != routingIncidentLatchStoreContractV1 {
			return nil, errors.New("routing incident latch store contract is unsupported")
		}
		items = append(items, envelope.Item)
	}
	return items, nil
}

func (s *routingObserverFileStore) LoadOutbox() ([]routingIncidentOutboxItem, error) {
	var envelopes []routingOutboxEnvelope
	if err := s.loadDirectory(s.outboxDir, &envelopes); err != nil {
		return nil, err
	}
	items := make([]routingIncidentOutboxItem, 0, len(envelopes))
	for _, envelope := range envelopes {
		if envelope.ContractVersion != routingIncidentOutboxStoreContractV1 {
			return nil, errors.New("routing incident outbox store contract is unsupported")
		}
		items = append(items, envelope.Item)
	}
	return items, nil
}

func (s *routingObserverFileStore) PutScope(item routingStoredScope) error {
	return s.writeEnvelope(s.scopesDir, routingObserverScopeFileName(item.Scope.GroupID, item.Scope.CanonicalModel), routingScopeEnvelope{
		ContractVersion: routingObserverScopeStoreContractV1,
		Item:            item,
	})
}

func (s *routingObserverFileStore) DeleteScope(scopeKey string) error {
	groupID, model, err := parseRoutingScopeKey(scopeKey)
	if err != nil {
		return err
	}
	return s.deleteEnvelope(s.scopesDir, routingObserverScopeFileName(groupID, model))
}

func (s *routingObserverFileStore) PutLatch(item routingIncidentLatch) error {
	return s.writeEnvelope(s.latchesDir, routingObserverIdentityFileName(item.IncidentID), routingLatchEnvelope{
		ContractVersion: routingIncidentLatchStoreContractV1,
		Item:            item,
	})
}

func (s *routingObserverFileStore) DeleteLatch(incidentID string) error {
	return s.deleteEnvelope(s.latchesDir, routingObserverIdentityFileName(incidentID))
}

func (s *routingObserverFileStore) PutOutbox(item routingIncidentOutboxItem) error {
	return s.writeEnvelope(s.outboxDir, routingObserverIdentityFileName(item.IncidentID), routingOutboxEnvelope{
		ContractVersion: routingIncidentOutboxStoreContractV1,
		Item:            item,
	})
}

func (s *routingObserverFileStore) DeleteOutbox(incidentID string) error {
	return s.deleteEnvelope(s.outboxDir, routingObserverIdentityFileName(incidentID))
}

func (s *routingObserverFileStore) loadDirectory(directory string, target any) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("read routing observer store: %w", err)
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("routing observer store contains a symbolic link")
		}
		paths = append(paths, filepath.Join(directory, entry.Name()))
	}
	sort.Strings(paths)
	values := make([]json.RawMessage, 0, len(paths))
	for _, path := range paths {
		payload, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read routing observer record: %w", err)
		}
		values = append(values, payload)
	}
	combined, err := json.Marshal(values)
	if err != nil {
		return err
	}
	rawValues := []json.RawMessage{}
	if err := json.Unmarshal(combined, &rawValues); err != nil {
		return err
	}
	switch typed := target.(type) {
	case *[]routingScopeEnvelope:
		for _, raw := range rawValues {
			var envelope routingScopeEnvelope
			if err := decodeRoutingObserverJSON(raw, &envelope); err != nil {
				return fmt.Errorf("decode routing observer scope: %w", err)
			}
			*typed = append(*typed, envelope)
		}
	case *[]routingLatchEnvelope:
		for _, raw := range rawValues {
			var envelope routingLatchEnvelope
			if err := decodeRoutingObserverJSON(raw, &envelope); err != nil {
				return fmt.Errorf("decode routing incident latch: %w", err)
			}
			*typed = append(*typed, envelope)
		}
	case *[]routingOutboxEnvelope:
		for _, raw := range rawValues {
			var envelope routingOutboxEnvelope
			if err := decodeRoutingObserverJSON(raw, &envelope); err != nil {
				return fmt.Errorf("decode routing incident outbox: %w", err)
			}
			*typed = append(*typed, envelope)
		}
	default:
		return errors.New("routing observer store target is unsupported")
	}
	return nil
}

func decodeRoutingObserverJSON(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func (s *routingObserverFileStore) writeEnvelope(directory, name string, value any) error {
	payload, err := canonicalJSON(value)
	if err != nil {
		return fmt.Errorf("serialize routing observer record: %w", err)
	}
	if s.atomicWriteHook != nil {
		if err := s.atomicWriteHook("before_create"); err != nil {
			return err
		}
	}
	temporary, err := os.CreateTemp(directory, "."+name+".tmp-")
	if err != nil {
		return fmt.Errorf("create routing observer temporary record: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("chmod routing observer temporary record: %w", err)
	}
	if _, err := temporary.Write(payload); err != nil {
		return fmt.Errorf("write routing observer temporary record: %w", err)
	}
	if s.atomicWriteHook != nil {
		if err := s.atomicWriteHook("before_file_sync"); err != nil {
			return err
		}
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync routing observer temporary record: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close routing observer temporary record: %w", err)
	}
	if s.atomicWriteHook != nil {
		if err := s.atomicWriteHook("before_rename"); err != nil {
			return err
		}
	}
	if err := os.Rename(temporaryPath, filepath.Join(directory, name)); err != nil {
		return fmt.Errorf("commit routing observer record: %w", err)
	}
	committed = true
	if s.atomicWriteHook != nil {
		if err := s.atomicWriteHook("before_directory_sync"); err != nil {
			return err
		}
	}
	if err := syncRoutingObserverDirectory(directory); err != nil {
		return err
	}
	return nil
}

func (s *routingObserverFileStore) deleteEnvelope(directory, name string) error {
	path := filepath.Join(directory, name)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete routing observer record: %w", err)
	}
	return syncRoutingObserverDirectory(directory)
}

func syncRoutingObserverDirectory(directory string) error {
	handle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open routing observer directory for sync: %w", err)
	}
	if err := handle.Sync(); err != nil {
		syncErr := fmt.Errorf("sync routing observer directory: %w", err)
		if closeErr := handle.Close(); closeErr != nil {
			return errors.Join(syncErr, fmt.Errorf("close routing observer directory: %w", closeErr))
		}
		return syncErr
	}
	if err := handle.Close(); err != nil {
		return fmt.Errorf("close routing observer directory: %w", err)
	}
	return nil
}

func routingObserverScopeFileName(groupID int64, model string) string {
	hash, _ := routingCanonicalHash(struct {
		GroupID int64  `json:"group_id"`
		Model   string `json:"model"`
	}{groupID, model})
	return "scope-" + strings.TrimPrefix(hash, "sha256:") + ".json"
}

func routingObserverIdentityFileName(identity string) string {
	return "incident-" + strings.TrimPrefix(identity, "hmac-sha256:") + ".json"
}

func routingScopeKey(groupID int64, model string) string {
	return fmt.Sprintf("%d\x00%s", groupID, model)
}

func parseRoutingScopeKey(value string) (int64, string, error) {
	separator := strings.IndexByte(value, 0)
	if separator <= 0 || separator == len(value)-1 {
		return 0, "", errors.New("routing observer scope key is invalid")
	}
	groupID, err := strconv.ParseInt(value[:separator], 10, 64)
	if err != nil || groupID <= 0 {
		return 0, "", errors.New("routing observer scope key group is invalid")
	}
	return groupID, value[separator+1:], nil
}
