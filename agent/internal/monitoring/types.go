// SPDX-License-Identifier: AGPL-3.0-only
package monitoring

import "time"

type Threshold struct {
	Op       string   `json:"op"`
	Warning  *float64 `json:"warning"`
	Critical *float64 `json:"critical"`
}

type Hysteresis struct {
	RaiseSamples int `json:"raise_samples"`
	ClearSamples int `json:"clear_samples"`
}

type Schedule struct {
	IntervalSeconds int `json:"interval_seconds"`
}

type Definition struct {
	Key        string         `json:"key"`
	Type       string         `json:"type"`
	Enabled    bool           `json:"enabled"`
	Schedule   Schedule       `json:"schedule"`
	Threshold  *Threshold     `json:"threshold"`
	Hysteresis Hysteresis     `json:"hysteresis"`
	Params     map[string]any `json:"params"`
}

type Assignment struct {
	Definition       Definition `json:"definition"`
	PolicyID         string     `json:"policy_id"`
	PolicyRevisionID string     `json:"policy_revision_id"`
}

type Result struct {
	ID               string         `json:"id"`
	PolicyID         string         `json:"policy_id"`
	PolicyRevisionID string         `json:"policy_revision_id"`
	CheckKey         string         `json:"check_key"`
	Status           string         `json:"status"`
	Value            *float64       `json:"value"`
	Detail           map[string]any `json:"detail"`
	EvaluatedAt      time.Time      `json:"evaluated_at"`
}

type ResultAck struct {
	OK         bool `json:"ok"`
	Accepted   int  `json:"accepted"`
	Duplicates int  `json:"duplicates"`
}
