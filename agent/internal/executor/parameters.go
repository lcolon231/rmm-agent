// SPDX-License-Identifier: AGPL-3.0-only

package executor

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	ParameterString  = "string"
	ParameterNumber  = "number"
	ParameterBoolean = "boolean"
	ParameterChoice  = "choice"
	ParameterSecret  = "secret"
)

var parameterKeyPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)

// ParameterValue is the agent-side typed binding contract. Values arrive only
// inside a signed, negotiated future command schema; Secret controls output
// redaction and never changes quoting semantics.
type ParameterValue struct {
	Key    string
	Kind   string
	Value  any
	Secret bool
}

func normalizedParameter(value ParameterValue) (string, error) {
	if !parameterKeyPattern.MatchString(value.Key) {
		return "", errors.New("unsupported parameter key")
	}
	switch value.Kind {
	case ParameterString, ParameterChoice, ParameterSecret:
		text, ok := value.Value.(string)
		if !ok {
			return "", fmt.Errorf("parameter %s requires a string", value.Key)
		}
		return text, nil
	case ParameterBoolean:
		boolean, ok := value.Value.(bool)
		if !ok {
			return "", fmt.Errorf("parameter %s requires a boolean", value.Key)
		}
		return strconv.FormatBool(boolean), nil
	case ParameterNumber:
		switch number := value.Value.(type) {
		case json.Number:
			parsed, err := number.Float64()
			if err != nil || math.IsInf(parsed, 0) || math.IsNaN(parsed) {
				return "", fmt.Errorf("parameter %s requires a finite number", value.Key)
			}
			return number.String(), nil
		case float64:
			if math.IsInf(number, 0) || math.IsNaN(number) {
				return "", fmt.Errorf("parameter %s requires a finite number", value.Key)
			}
			return strconv.FormatFloat(number, 'g', -1, 64), nil
		case int:
			return strconv.Itoa(number), nil
		case int64:
			return strconv.FormatInt(number, 10), nil
		default:
			return "", fmt.Errorf("parameter %s requires a number", value.Key)
		}
	default:
		return "", fmt.Errorf("parameter %s has unsupported kind", value.Key)
	}
}

func quotePowerShell(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func quoteShell(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

// RenderParameterizedScript binds data to generated variables. It never
// substitutes tokens inside caller-controlled script source.
func RenderParameterizedScript(kind, script string, parameters []ParameterValue) (string, error) {
	if len(parameters) == 0 {
		return script, nil
	}
	if len(parameters) > 32 {
		return "", errors.New("at most 32 parameters are supported")
	}
	seen := make(map[string]struct{}, len(parameters))
	lines := make([]string, 0, len(parameters)*2+1)
	for _, parameter := range parameters {
		folded := strings.ToLower(parameter.Key)
		if _, exists := seen[folded]; exists {
			return "", errors.New("parameter keys must be unique ignoring case")
		}
		seen[folded] = struct{}{}
		value, err := normalizedParameter(parameter)
		if err != nil {
			return "", err
		}
		variable := "NL_PARAM_" + parameter.Key
		switch kind {
		case KindPowerShell:
			literal := quotePowerShell(value)
			if parameter.Kind == ParameterBoolean {
				if value == "true" {
					literal = "$true"
				} else {
					literal = "$false"
				}
			} else if parameter.Kind == ParameterNumber {
				literal = value
			}
			lines = append(lines, "$"+variable+" = "+literal)
		case KindShell:
			lines = append(lines, variable+"="+quoteShell(value), "export "+variable)
		default:
			return "", errors.New("parameter binding is unsupported for this command kind")
		}
	}
	lines = append(lines, script)
	return strings.Join(lines, "\n"), nil
}

// RedactParameterSecrets removes exact secret values from captured output.
// Longest-first replacement prevents a shorter secret from exposing a suffix
// of another. Empty secrets are ignored because replacing them corrupts all text.
func RedactParameterSecrets(text string, parameters []ParameterValue) string {
	values := make([]string, 0)
	seen := map[string]struct{}{}
	for _, parameter := range parameters {
		if !parameter.Secret && parameter.Kind != ParameterSecret {
			continue
		}
		value, err := normalizedParameter(parameter)
		if err != nil || value == "" {
			continue
		}
		if _, exists := seen[value]; !exists {
			seen[value] = struct{}{}
			values = append(values, value)
		}
	}
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	for _, value := range values {
		text = strings.ReplaceAll(text, value, "[redacted]")
	}
	return text
}
