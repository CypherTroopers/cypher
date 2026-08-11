// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package schema

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

const (
	RegistryFormat           = "cph.aiinfra.ccse.registry"
	CCSEVersion              = "CCSE-v1"
	MaxRegistryJSONBytes     = 4 << 20
	ProductionMessageIDFloor = uint32(0x00010001)

	MessageTypeProviderIdentity               = uint32(0x00010001)
	MessageTypeAgentIdentity                  = uint32(0x00010002)
	MessageTypeHostIdentity                   = uint32(0x00010003)
	MessageTypeDeviceIdentity                 = uint32(0x00010004)
	MessageTypeMinerIdentity                  = uint32(0x00010005)
	MessageTypeRunnerIdentity                 = uint32(0x00010006)
	MessageTypeBuyerIdentity                  = uint32(0x00010007)
	MessageTypeServiceIdentity                = uint32(0x00010008)
	MessageTypeKeyLifecycle                   = uint32(0x00010009)
	MessageTypePolicyBundle                   = uint32(0x0001000a)
	MessageTypeAuditEvent                     = uint32(0x0001000b)
	MessageTypeEvidenceRecord                 = uint32(0x0001000c)
	MessageTypeExperimentPlan                 = uint32(0x0001000d)
	MessageTypeOwnershipTransferAuthorization = uint32(0x0001000e)
)

var (
	ErrInvalidRegistry       = errors.New("aiinfra schema: invalid registry")
	ErrDuplicateMessageID    = errors.New("aiinfra schema: duplicate message type identifier")
	ErrDuplicateName         = errors.New("aiinfra schema: duplicate name")
	ErrInvalidFieldOrder     = errors.New("aiinfra schema: field order is not contiguous")
	ErrUnknownFieldType      = errors.New("aiinfra schema: unknown or forbidden field type")
	ErrInvalidField          = errors.New("aiinfra schema: invalid field")
	ErrInvalidLimits         = errors.New("aiinfra schema: invalid limits")
	ErrUnknownMessageType    = errors.New("aiinfra schema: unknown nested message type")
	ErrReservedMessageID     = errors.New("aiinfra schema: production message uses a reserved identifier")
	ErrNonCanonicalOrdering  = errors.New("aiinfra schema: entries are not in canonical order")
	ErrRecursiveProjection   = errors.New("aiinfra schema: recursive signing projection")
	ErrEncodedBoundTooSmall  = errors.New("aiinfra schema: max encoded bytes cannot contain declared canonical value")
	ErrFixedWidthBound       = errors.New("aiinfra schema: fixed-width max encoded bytes is not exact")
	fieldNamePattern         = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	idSymbolPattern          = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	knownCanonicalFieldTypes = map[string]struct{}{
		"bool": {}, "uint32": {}, "uint64": {}, "int64": {},
		"enum_uint32": {}, "string": {}, "bytes": {},
		"fixed_bytes_16": {}, "fixed_bytes_32": {}, "fixed_bytes_64": {},
		"message": {},
	}
)

//go:embed ccse/v1/registry.json common/v1/common.proto foundation/v1/foundation.proto transport/v1/foundation_transport.proto
var schemaFiles embed.FS

// Version is an unsigned two-component schema version.
type Version struct {
	Major uint32 `json:"major"`
	Minor uint32 `json:"minor"`
}

// ReservedMessageTypeRange prevents test/conformance identifiers from leaking
// into production authorization records.
type ReservedMessageTypeRange struct {
	First   uint32 `json:"first"`
	Last    uint32 `json:"last"`
	Purpose string `json:"purpose"`
}

// Limits bounds parsing and canonical projection work for a message or nested
// structure. Services may apply stricter policy limits.
type Limits struct {
	MaxPayloadBytes    int `json:"max_payload_bytes"`
	MaxFields          int `json:"max_fields"`
	MaxCollectionItems int `json:"max_collection_items"`
	MaxNestingDepth    int `json:"max_nesting_depth"`
}

// Field fixes one position in a CCSE signing projection. Critical is a pointer
// so validation can distinguish an explicit false value from an omitted rule.
type Field struct {
	Order           int    `json:"order"`
	Name            string `json:"name"`
	Type            string `json:"type"`
	MessageType     string `json:"message_type,omitempty"`
	Presence        string `json:"presence"`
	Collection      string `json:"collection"`
	Critical        *bool  `json:"critical"`
	MaxEncodedBytes int    `json:"max_encoded_bytes"`
	MaxItems        int    `json:"max_items"`
}

// Projection defines an ordered nested CCSE structure without allocating a
// top-level message type identifier.
type Projection struct {
	Name   string  `json:"name"`
	Limits Limits  `json:"limits"`
	Fields []Field `json:"fields"`
}

// Message defines a production signed payload projection.
type Message struct {
	MessageTypeID      uint32  `json:"message_type_id"`
	IDSymbol           string  `json:"id_symbol"`
	Name               string  `json:"name"`
	SchemaVersion      Version `json:"schema_version"`
	Purpose            string  `json:"purpose"`
	UnknownFieldPolicy string  `json:"unknown_field_policy"`
	Limits             Limits  `json:"limits"`
	Fields             []Field `json:"fields"`
}

// Registry is deliberately map-free. Its canonical JSON therefore has fixed
// member ordering and retains the explicit order of messages and fields.
type Registry struct {
	Format                       string                     `json:"format"`
	RegistryVersion              Version                    `json:"registry_version"`
	CCSEVersion                  string                     `json:"ccse_version"`
	ProductionMessageTypeIDFloor uint32                     `json:"production_message_type_id_floor"`
	ReservedMessageTypeRanges    []ReservedMessageTypeRange `json:"reserved_message_type_ranges"`
	Structures                   []Projection               `json:"structures"`
	Messages                     []Message                  `json:"messages"`
}

// LoadDefault parses and validates the embedded production registry. A fresh
// value is returned on every call, preventing mutation of process-global state.
func LoadDefault() (Registry, error) {
	data, err := schemaFiles.ReadFile("ccse/v1/registry.json")
	if err != nil {
		return Registry{}, fmt.Errorf("%w: read embedded registry: %v", ErrInvalidRegistry, err)
	}
	return Parse(data)
}

// Parse strictly decodes and validates a registry document.
func Parse(data []byte) (Registry, error) {
	if len(data) == 0 || len(data) > MaxRegistryJSONBytes {
		return Registry{}, fmt.Errorf("%w: registry JSON size %d", ErrInvalidRegistry, len(data))
	}
	if err := rejectDuplicateJSONMembers(data); err != nil {
		return Registry{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var registry Registry
	if err := decoder.Decode(&registry); err != nil {
		return Registry{}, fmt.Errorf("%w: decode: %v", ErrInvalidRegistry, err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Registry{}, err
	}
	if err := registry.Validate(); err != nil {
		return Registry{}, err
	}
	return registry, nil
}

func rejectDuplicateJSONMembers(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := inspectJSONValue(decoder); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRegistry, err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("%w: trailing JSON value", ErrInvalidRegistry)
		}
		return fmt.Errorf("%w: trailing data: %v", ErrInvalidRegistry, err)
	}
	return nil
}

func inspectJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		members := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := members[key]; duplicate {
				return fmt.Errorf("duplicate JSON member %q", key)
			}
			members[key] = struct{}{}
			if err := inspectJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := inspectJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return fmt.Errorf("%w: trailing JSON value", ErrInvalidRegistry)
	}
	return fmt.Errorf("%w: trailing data: %v", ErrInvalidRegistry, err)
}

// Validate enforces uniqueness, canonical ordering, fixed production ID
// ranges, projection ordering, known canonical types, and positive bounds.
func (r Registry) Validate() error {
	if r.Format != RegistryFormat || r.CCSEVersion != CCSEVersion || r.RegistryVersion.Major == 0 {
		return fmt.Errorf("%w: unsupported format or version", ErrInvalidRegistry)
	}
	if r.ProductionMessageTypeIDFloor != ProductionMessageIDFloor {
		return fmt.Errorf("%w: production message floor %d", ErrInvalidRegistry, r.ProductionMessageTypeIDFloor)
	}
	if len(r.ReservedMessageTypeRanges) == 0 || len(r.Structures) == 0 || len(r.Messages) == 0 {
		return fmt.Errorf("%w: empty registry section", ErrInvalidRegistry)
	}
	if err := validateReservedRanges(r.ReservedMessageTypeRanges); err != nil {
		return err
	}

	knownMessages := make(map[string]struct{}, len(r.Structures)+len(r.Messages))
	for _, projection := range r.Structures {
		if _, exists := knownMessages[projection.Name]; exists {
			return fmt.Errorf("%w: %s", ErrDuplicateName, projection.Name)
		}
		knownMessages[projection.Name] = struct{}{}
	}
	for _, message := range r.Messages {
		if _, exists := knownMessages[message.Name]; exists {
			return fmt.Errorf("%w: %s", ErrDuplicateName, message.Name)
		}
		knownMessages[message.Name] = struct{}{}
	}

	for _, projection := range r.Structures {
		if err := validateProjection(projection.Name, projection.Limits, projection.Fields, knownMessages); err != nil {
			return err
		}
	}

	ids := make(map[uint32]struct{}, len(r.Messages))
	symbols := make(map[string]struct{}, len(r.Messages))
	for i, message := range r.Messages {
		if i > 0 && r.Messages[i-1].MessageTypeID == message.MessageTypeID {
			return fmt.Errorf("%w: %d", ErrDuplicateMessageID, message.MessageTypeID)
		}
		if i > 0 && r.Messages[i-1].MessageTypeID > message.MessageTypeID {
			return fmt.Errorf("%w: messages", ErrNonCanonicalOrdering)
		}
		if message.MessageTypeID < r.ProductionMessageTypeIDFloor || messageIDReserved(message.MessageTypeID, r.ReservedMessageTypeRanges) {
			return fmt.Errorf("%w: %d", ErrReservedMessageID, message.MessageTypeID)
		}
		if _, exists := ids[message.MessageTypeID]; exists {
			return fmt.Errorf("%w: %d", ErrDuplicateMessageID, message.MessageTypeID)
		}
		ids[message.MessageTypeID] = struct{}{}
		if !idSymbolPattern.MatchString(message.IDSymbol) {
			return fmt.Errorf("%w: invalid ID symbol %q", ErrInvalidRegistry, message.IDSymbol)
		}
		if _, exists := symbols[message.IDSymbol]; exists {
			return fmt.Errorf("%w: %s", ErrDuplicateName, message.IDSymbol)
		}
		symbols[message.IDSymbol] = struct{}{}
		if message.SchemaVersion.Major == 0 || strings.TrimSpace(message.Purpose) == "" || message.UnknownFieldPolicy != "reject" {
			return fmt.Errorf("%w: message %s metadata", ErrInvalidRegistry, message.Name)
		}
		if err := validateProjection(message.Name, message.Limits, message.Fields, knownMessages); err != nil {
			return err
		}
	}
	return validateProjectionGraph(r.Structures, r.Messages)
}

func validateProjectionGraph(structures []Projection, messages []Message) error {
	graph := make(map[string][]string, len(structures)+len(messages))
	for _, projection := range structures {
		graph[projection.Name] = nestedMessageTypes(projection.Fields)
	}
	for _, message := range messages {
		graph[message.Name] = nestedMessageTypes(message.Fields)
	}
	const (
		visiting = uint8(1)
		visited  = uint8(2)
	)
	state := make(map[string]uint8, len(graph))
	var visit func(string) error
	visit = func(name string) error {
		switch state[name] {
		case visiting:
			return fmt.Errorf("%w: %s", ErrRecursiveProjection, name)
		case visited:
			return nil
		}
		state[name] = visiting
		for _, child := range graph[name] {
			if err := visit(child); err != nil {
				return err
			}
		}
		state[name] = visited
		return nil
	}
	for name := range graph {
		if err := visit(name); err != nil {
			return err
		}
	}
	return nil
}

func nestedMessageTypes(fields []Field) []string {
	out := make([]string, 0)
	for _, field := range fields {
		if field.Type == "message" {
			out = append(out, field.MessageType)
		}
	}
	return out
}

func validateReservedRanges(ranges []ReservedMessageTypeRange) error {
	for i, reserved := range ranges {
		if reserved.First == 0 || reserved.Last < reserved.First || strings.TrimSpace(reserved.Purpose) == "" {
			return fmt.Errorf("%w: invalid reserved range", ErrInvalidRegistry)
		}
		if i > 0 && ranges[i-1].Last >= reserved.First {
			return fmt.Errorf("%w: reserved ranges", ErrNonCanonicalOrdering)
		}
	}
	return nil
}

func messageIDReserved(id uint32, ranges []ReservedMessageTypeRange) bool {
	index := sort.Search(len(ranges), func(i int) bool { return ranges[i].Last >= id })
	return index < len(ranges) && ranges[index].First <= id
}

func validateProjection(name string, limits Limits, fields []Field, knownMessages map[string]struct{}) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("%w: empty projection name", ErrInvalidRegistry)
	}
	if limits.MaxPayloadBytes <= 0 || limits.MaxFields <= 0 || limits.MaxCollectionItems <= 0 || limits.MaxNestingDepth <= 0 {
		return fmt.Errorf("%w: %s", ErrInvalidLimits, name)
	}
	if len(fields) == 0 || len(fields) > limits.MaxFields {
		return fmt.Errorf("%w: %s field count", ErrInvalidLimits, name)
	}
	fieldNames := make(map[string]struct{}, len(fields))
	for i, field := range fields {
		if field.Order != i+1 {
			return fmt.Errorf("%w: %s.%s has order %d, want %d", ErrInvalidFieldOrder, name, field.Name, field.Order, i+1)
		}
		if !fieldNamePattern.MatchString(field.Name) {
			return fmt.Errorf("%w: invalid name %s.%s", ErrInvalidField, name, field.Name)
		}
		if _, exists := fieldNames[field.Name]; exists {
			return fmt.Errorf("%w: %s.%s", ErrDuplicateName, name, field.Name)
		}
		fieldNames[field.Name] = struct{}{}
		if _, known := knownCanonicalFieldTypes[field.Type]; !known {
			return fmt.Errorf("%w: %s.%s type %q", ErrUnknownFieldType, name, field.Name, field.Type)
		}
		if field.Presence != "required" && field.Presence != "optional" {
			return fmt.Errorf("%w: %s.%s presence", ErrInvalidField, name, field.Name)
		}
		if field.Collection != "scalar" && field.Collection != "ordered_list" && field.Collection != "set" {
			return fmt.Errorf("%w: %s.%s collection", ErrInvalidField, name, field.Name)
		}
		if field.Presence == "optional" && field.Collection != "scalar" {
			return fmt.Errorf("%w: optional collection %s.%s", ErrInvalidField, name, field.Name)
		}
		if field.Critical == nil {
			return fmt.Errorf("%w: %s.%s missing critical rule", ErrInvalidField, name, field.Name)
		}
		if field.MaxEncodedBytes <= 0 || field.MaxEncodedBytes > limits.MaxPayloadBytes || field.MaxItems <= 0 || field.MaxItems > limits.MaxCollectionItems {
			return fmt.Errorf("%w: %s.%s bounds", ErrInvalidLimits, name, field.Name)
		}
		if field.Collection == "scalar" && field.MaxItems != 1 {
			return fmt.Errorf("%w: scalar %s.%s max_items", ErrInvalidLimits, name, field.Name)
		}
		minimumBound, err := minimumEncodedBound(field)
		if err != nil {
			return fmt.Errorf("%w: %s.%s: %v", ErrInvalidLimits, name, field.Name, err)
		}
		if field.MaxEncodedBytes < minimumBound {
			return fmt.Errorf("%w: %s.%s has %d, needs at least %d", ErrEncodedBoundTooSmall, name, field.Name, field.MaxEncodedBytes, minimumBound)
		}
		if fixedByteWidth(field.Type) != 0 && field.MaxEncodedBytes != minimumBound {
			return fmt.Errorf("%w: %s.%s has %d, want %d", ErrFixedWidthBound, name, field.Name, field.MaxEncodedBytes, minimumBound)
		}
		if field.Type == "message" {
			if _, known := knownMessages[field.MessageType]; !known {
				return fmt.Errorf("%w: %s.%s -> %s", ErrUnknownMessageType, name, field.Name, field.MessageType)
			}
		} else if field.MessageType != "" {
			return fmt.Errorf("%w: non-message %s.%s has message_type", ErrInvalidField, name, field.Name)
		}
	}
	return nil
}

// minimumEncodedBound computes the smallest bound capable of holding the
// declared maximum item count. Strings and byte strings include len32. Optional
// scalars include their presence byte. Collections include count32 and the
// len32 frame written around every canonical element by EncodedList/EncodedSet.
func minimumEncodedBound(field Field) (int, error) {
	elementBytes := primitiveEncodedSize(field.Type)
	if field.Collection == "scalar" {
		minimum := elementBytes
		if field.Presence == "optional" {
			if minimum == maxInt() {
				return 0, errors.New("encoded bound overflow")
			}
			minimum++
		}
		return minimum, nil
	}
	perItem, overflow := checkedAdd(4, elementBytes)
	if overflow {
		return 0, errors.New("encoded element bound overflow")
	}
	items, overflow := checkedMultiply(field.MaxItems, perItem)
	if overflow {
		return 0, errors.New("encoded collection bound overflow")
	}
	minimum, overflow := checkedAdd(4, items)
	if overflow {
		return 0, errors.New("encoded collection bound overflow")
	}
	return minimum, nil
}

func primitiveEncodedSize(fieldType string) int {
	switch fieldType {
	case "bool":
		return 1
	case "uint32", "enum_uint32":
		return 4
	case "uint64", "int64":
		return 8
	case "string", "bytes":
		return 4
	case "fixed_bytes_16":
		return 4 + 16
	case "fixed_bytes_32":
		return 4 + 32
	case "fixed_bytes_64":
		return 4 + 64
	case "message":
		// Scalar messages are projected inline without an extra frame. Message
		// collections receive the same outer len32 element frame as every
		// EncodedList/EncodedSet member. The referenced projection validates
		// its own body bounds.
		return 0
	default:
		return 0
	}
}

func fixedByteWidth(fieldType string) int {
	switch fieldType {
	case "fixed_bytes_16":
		return 16
	case "fixed_bytes_32":
		return 32
	case "fixed_bytes_64":
		return 64
	default:
		return 0
	}
}

func checkedAdd(left, right int) (int, bool) {
	if left < 0 || right < 0 || left > maxInt()-right {
		return 0, true
	}
	return left + right, false
}

func checkedMultiply(left, right int) (int, bool) {
	if left < 0 || right < 0 || (left != 0 && right > maxInt()/left) {
		return 0, true
	}
	return left * right, false
}

func maxInt() int {
	return int(^uint(0) >> 1)
}

// CanonicalJSON returns the registry's deterministic compact JSON form after
// validation. It is an artifact commitment, not a CCSE payload projection.
func (r Registry) CanonicalJSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("%w: canonical marshal: %v", ErrInvalidRegistry, err)
	}
	return data, nil
}

// SHA256 returns SHA-256 over CanonicalJSON.
func (r Registry) SHA256() ([sha256.Size]byte, error) {
	data, err := r.CanonicalJSON()
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(data), nil
}

// SHA256Hex returns the lower-case hexadecimal registry commitment.
func (r Registry) SHA256Hex() (string, error) {
	digest, err := r.SHA256()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}

// LookupMessage returns a copy of the registry entry for an exact production
// message type identifier.
func (r Registry) LookupMessage(id uint32) (Message, bool) {
	index := sort.Search(len(r.Messages), func(i int) bool { return r.Messages[i].MessageTypeID >= id })
	if index == len(r.Messages) || r.Messages[index].MessageTypeID != id {
		return Message{}, false
	}
	return r.Messages[index], true
}

// EmbeddedRegistryJSON returns a detached copy of the reviewed source file.
func EmbeddedRegistryJSON() ([]byte, error) {
	data, err := schemaFiles.ReadFile("ccse/v1/registry.json")
	return append([]byte(nil), data...), err
}

// EmbeddedProtoSources returns detached source bytes indexed by stable logical
// path. The returned slice, rather than a map, keeps iteration deterministic.
func EmbeddedProtoSources() ([]ProtoSource, error) {
	paths := []string{"common/v1/common.proto", "foundation/v1/foundation.proto", "transport/v1/foundation_transport.proto"}
	out := make([]ProtoSource, 0, len(paths))
	for _, path := range paths {
		data, err := schemaFiles.ReadFile(path)
		if err != nil {
			return nil, err
		}
		out = append(out, ProtoSource{Path: path, Source: append([]byte(nil), data...)})
	}
	return out, nil
}

// ProtoSource is one embedded transport schema.
type ProtoSource struct {
	Path   string
	Source []byte
}
