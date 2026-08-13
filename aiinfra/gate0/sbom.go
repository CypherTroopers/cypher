// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package gate0

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

const SPDXVersion = "SPDX-2.3"

type SBOMComponent struct {
	SPDXID           string
	Name             string
	Version          string
	DownloadLocation string
	SHA256           string
}

type SBOMInput struct {
	Name              string
	DocumentNamespace string
	CreatedAt         time.Time
	Creator           string
	Components        []SBOMComponent
}

type SPDXDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      SPDXCreationInfo   `json:"creationInfo"`
	Packages          []SPDXPackage      `json:"packages"`
	Relationships     []SPDXRelationship `json:"relationships"`
}

type SPDXCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type SPDXPackage struct {
	SPDXID           string         `json:"SPDXID"`
	Name             string         `json:"name"`
	VersionInfo      string         `json:"versionInfo"`
	DownloadLocation string         `json:"downloadLocation"`
	FilesAnalyzed    bool           `json:"filesAnalyzed"`
	Checksums        []SPDXChecksum `json:"checksums"`
}

type SPDXChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type SPDXRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

func GenerateSPDX(input SBOMInput) ([]byte, error) {
	if !validIdentifier(input.Name) || !validIdentifier(input.DocumentNamespace) || input.CreatedAt.IsZero() ||
		!validIdentifier(input.Creator) || len(input.Components) == 0 {
		return nil, fmt.Errorf("%w: SPDX input", ErrInvalidEvidence)
	}
	components := append([]SBOMComponent(nil), input.Components...)
	sort.Slice(components, func(i, j int) bool { return components[i].SPDXID < components[j].SPDXID })
	document := SPDXDocument{SPDXVersion: SPDXVersion, DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT",
		Name: input.Name, DocumentNamespace: input.DocumentNamespace,
		CreationInfo: SPDXCreationInfo{Created: input.CreatedAt.UTC().Format(time.RFC3339), Creators: []string{input.Creator}},
		Packages:     make([]SPDXPackage, 0, len(components)), Relationships: make([]SPDXRelationship, 0, len(components))}
	for index, component := range components {
		if !validIdentifier(component.SPDXID) || !validIdentifier(component.Name) || !validIdentifier(component.Version) ||
			!validIdentifier(component.DownloadLocation) || !validDigest(DigestPrefix+component.SHA256) ||
			(index > 0 && component.SPDXID == components[index-1].SPDXID) {
			return nil, fmt.Errorf("%w: SPDX component", ErrInvalidEvidence)
		}
		document.Packages = append(document.Packages, SPDXPackage{SPDXID: component.SPDXID, Name: component.Name,
			VersionInfo: component.Version, DownloadLocation: component.DownloadLocation, FilesAnalyzed: false,
			Checksums: []SPDXChecksum{{Algorithm: "SHA256", ChecksumValue: component.SHA256}}})
		document.Relationships = append(document.Relationships, SPDXRelationship{SPDXElementID: "SPDXRef-DOCUMENT",
			RelationshipType: "DESCRIBES", RelatedSPDXElement: component.SPDXID})
	}
	return json.Marshal(document)
}

func VerifySPDX(data []byte, expectedNamespace string) (SPDXDocument, error) {
	if len(data) == 0 || len(data) > maxJSONBytes {
		return SPDXDocument{}, fmt.Errorf("%w: SPDX size", ErrInvalidEvidence)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document SPDXDocument
	if err := decoder.Decode(&document); err != nil {
		return SPDXDocument{}, fmt.Errorf("%w: SPDX decode: %v", ErrInvalidEvidence, err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return SPDXDocument{}, err
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, data) || document.SPDXVersion != SPDXVersion ||
		document.DataLicense != "CC0-1.0" || document.SPDXID != "SPDXRef-DOCUMENT" ||
		document.DocumentNamespace != expectedNamespace || len(document.Packages) == 0 ||
		len(document.Packages) != len(document.Relationships) || len(document.CreationInfo.Creators) != 1 {
		return SPDXDocument{}, fmt.Errorf("%w: SPDX policy", ErrInvalidEvidence)
	}
	if _, err := time.Parse(time.RFC3339, document.CreationInfo.Created); err != nil {
		return SPDXDocument{}, fmt.Errorf("%w: SPDX created time", ErrInvalidEvidence)
	}
	for index, item := range document.Packages {
		if index > 0 && document.Packages[index-1].SPDXID >= item.SPDXID {
			return SPDXDocument{}, fmt.Errorf("%w: SPDX package order", ErrInvalidEvidence)
		}
		if item.FilesAnalyzed || len(item.Checksums) != 1 || item.Checksums[0].Algorithm != "SHA256" ||
			!validDigest(DigestPrefix+item.Checksums[0].ChecksumValue) {
			return SPDXDocument{}, fmt.Errorf("%w: SPDX package digest", ErrInvalidEvidence)
		}
		relationship := document.Relationships[index]
		if relationship.SPDXElementID != "SPDXRef-DOCUMENT" || relationship.RelationshipType != "DESCRIBES" ||
			relationship.RelatedSPDXElement != item.SPDXID {
			return SPDXDocument{}, fmt.Errorf("%w: SPDX relationship", ErrInvalidEvidence)
		}
	}
	return document, nil
}
