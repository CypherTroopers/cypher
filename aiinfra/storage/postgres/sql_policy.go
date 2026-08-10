// Copyright 2026 The Cypherium Authors
// This file is part of the Cypherium library.

package postgres

import (
	"fmt"
	"strings"
	"unicode"
)

var forbiddenBusinessSQLTokens = map[string]struct{}{
	"CPH_AIINFRA":                         {},
	"PG_CATALOG":                          {},
	"INFORMATION_SCHEMA":                  {},
	"SET_CONFIG":                          {},
	"PG_ADVISORY_LOCK":                    {},
	"PG_ADVISORY_XACT_LOCK":               {},
	"PG_TERMINATE_BACKEND":                {},
	"PG_CANCEL_BACKEND":                   {},
	"PG_RELOAD_CONF":                      {},
	"PG_CREATE_RESTORE_POINT":             {},
	"PG_LOGICAL_EMIT_MESSAGE":             {},
	"PG_NOTIFY":                           {},
	"PG_SLEEP":                            {},
	"PG_EXPORT_SNAPSHOT":                  {},
	"PG_PROMOTE":                          {},
	"PG_SWITCH_WAL":                       {},
	"PG_BACKUP_START":                     {},
	"PG_BACKUP_STOP":                      {},
	"PG_START_BACKUP":                     {},
	"PG_STOP_BACKUP":                      {},
	"PG_CREATE_LOGICAL_REPLICATION_SLOT":  {},
	"PG_CREATE_PHYSICAL_REPLICATION_SLOT": {},
	"PG_DROP_REPLICATION_SLOT":            {},
	"PG_WAL_REPLAY_PAUSE":                 {},
	"PG_WAL_REPLAY_RESUME":                {},
	"PG_IMPORT_SYSTEM_COLLATIONS":         {},
	"NEXTVAL":                             {},
	"SETVAL":                              {},
	"CURRVAL":                             {},
	"LO_IMPORT":                           {},
	"LO_EXPORT":                           {},
	"DBLINK":                              {},
}

func validateBusinessSQL(query string, access StatementAccess) error {
	tokens, err := businessSQLTokens(query)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStatementNotAllowed, err)
	}
	if len(tokens) == 0 {
		return fmt.Errorf("%w: SQL has no statement", ErrStatementNotAllowed)
	}
	root := tokens[0]
	allowedRoot := false
	if access&StatementExec != 0 {
		switch root {
		case "INSERT", "UPDATE", "DELETE", "MERGE", "WITH":
			allowedRoot = true
		}
	}
	if access&StatementQuery != 0 {
		switch root {
		case "SELECT", "WITH", "VALUES", "TABLE":
			allowedRoot = true
		}
	}
	if !allowedRoot {
		return fmt.Errorf("%w: %s is not valid for access mode %d", ErrStatementNotAllowed, root, access)
	}
	hasDataModification := false
	for _, token := range tokens {
		if isForbiddenBusinessSQLToken(token) {
			return fmt.Errorf("%w: forbidden SQL capability %s", ErrStatementNotAllowed, token)
		}
		if access == StatementQuery && token == "INTO" {
			return fmt.Errorf("%w: SELECT INTO is prohibited", ErrStatementNotAllowed)
		}
		switch token {
		case "INSERT", "UPDATE", "DELETE", "MERGE":
			hasDataModification = true
		}
	}
	if access == StatementQuery && hasDataModification {
		return fmt.Errorf("%w: query capability contains data modification", ErrStatementNotAllowed)
	}
	if access == StatementExec && root == "WITH" && !hasDataModification {
		return fmt.Errorf("%w: exec capability has no data modification", ErrStatementNotAllowed)
	}
	return nil
}

func isForbiddenBusinessSQLToken(token string) bool {
	if _, forbidden := forbiddenBusinessSQLTokens[token]; forbidden {
		return true
	}
	return strings.HasPrefix(token, "PG_ADVISORY_") ||
		strings.HasPrefix(token, "DBLINK_") ||
		strings.HasPrefix(token, "LO_")
}

// businessSQLTokens is deliberately a validator, not a general SQL parser. It
// rejects statement separators and malformed quoting, ignores string/comment
// contents, and returns unquoted and quoted identifiers for capability checks.
func businessSQLTokens(query string) ([]string, error) {
	var tokens []string
	for index := 0; index < len(query); {
		character := query[index]
		switch {
		case unicode.IsSpace(rune(character)):
			index++
		case character == ';':
			return nil, fmt.Errorf("multiple or terminated statements are prohibited")
		case character == '-' && index+1 < len(query) && query[index+1] == '-':
			index += 2
			for index < len(query) && query[index] != '\n' {
				index++
			}
		case character == '/' && index+1 < len(query) && query[index+1] == '*':
			var err error
			index, err = skipNestedBlockComment(query, index)
			if err != nil {
				return nil, err
			}
		case character == '\'':
			var err error
			index, err = skipQuotedSQL(query, index, '\'')
			if err != nil {
				return nil, err
			}
		case character == '"':
			end, identifier, err := readQuotedIdentifier(query, index)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, strings.ToUpper(identifier))
			index = end
		case (character == 'U' || character == 'u') && index+2 < len(query) &&
			query[index+1] == '&' && (query[index+2] == '\'' || query[index+2] == '"'):
			return nil, fmt.Errorf("Unicode-escaped SQL tokens are prohibited")
		case character == '$':
			end, skipped, err := skipDollarQuotedSQL(query, index)
			if err != nil {
				return nil, err
			}
			if skipped {
				index = end
			} else {
				index++
			}
		case isSQLIdentifierStart(character):
			start := index
			index++
			for index < len(query) && isSQLIdentifierContinue(query[index]) {
				index++
			}
			tokens = append(tokens, strings.ToUpper(query[start:index]))
		default:
			index++
		}
	}
	return tokens, nil
}

func skipNestedBlockComment(query string, start int) (int, error) {
	depth := 1
	for index := start + 2; index < len(query); {
		switch {
		case index+1 < len(query) && query[index] == '/' && query[index+1] == '*':
			depth++
			index += 2
		case index+1 < len(query) && query[index] == '*' && query[index+1] == '/':
			depth--
			index += 2
			if depth == 0 {
				return index, nil
			}
		default:
			index++
		}
	}
	return 0, fmt.Errorf("unterminated block comment")
}

func skipQuotedSQL(query string, start int, quote byte) (int, error) {
	for index := start + 1; index < len(query); index++ {
		if query[index] != quote {
			continue
		}
		if index+1 < len(query) && query[index+1] == quote {
			index++
			continue
		}
		return index + 1, nil
	}
	return 0, fmt.Errorf("unterminated quoted value")
}

func readQuotedIdentifier(query string, start int) (int, string, error) {
	var identifier strings.Builder
	for index := start + 1; index < len(query); index++ {
		if query[index] != '"' {
			identifier.WriteByte(query[index])
			continue
		}
		if index+1 < len(query) && query[index+1] == '"' {
			identifier.WriteByte('"')
			index++
			continue
		}
		return index + 1, identifier.String(), nil
	}
	return 0, "", fmt.Errorf("unterminated quoted identifier")
}

func skipDollarQuotedSQL(query string, start int) (int, bool, error) {
	endTag := start + 1
	for endTag < len(query) && (isSQLIdentifierContinue(query[endTag]) || query[endTag] == '$') {
		if query[endTag] == '$' {
			tag := query[start : endTag+1]
			closeAt := strings.Index(query[endTag+1:], tag)
			if closeAt < 0 {
				return 0, false, fmt.Errorf("unterminated dollar-quoted value")
			}
			return endTag + 1 + closeAt + len(tag), true, nil
		}
		endTag++
	}
	return start, false, nil
}

func isSQLIdentifierStart(character byte) bool {
	return character == '_' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z'
}

func isSQLIdentifierContinue(character byte) bool {
	return isSQLIdentifierStart(character) || character >= '0' && character <= '9' || character == '$'
}
