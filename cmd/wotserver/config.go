package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// fileConfig is the optional -config JSON. Every field is a pointer so
// an absent key leaves the corresponding flag alone: flags win when
// both are given, and the file only fills what the operator did not.
type fileConfig struct {
	Addr       *string `json:"addr"`
	PrivKey    *string `json:"privkey"`
	S1         *string `json:"s1"`
	S2         *string `json:"s2"`
	Flood      *string `json:"flood"`
	FloodKey   *string `json:"floodkey"`
	FloodFlow  *string `json:"floodflow"`
	Post       *string `json:"post"`
	PostKey    *string `json:"postkey"`
	PostFlow   *string `json:"postflow"`
	Defs       *string `json:"defs"`
	BaseApp    *string `json:"baseapp"`
	MaxNonce   *int64  `json:"maxnonce"`
	AnyVersion *bool   `json:"any_version"`
	Digest     *string `json:"digest"`
	Verbose    *bool   `json:"verbose"`
	DB         *string `json:"db"`
	User       *string `json:"user"`
	Pass       *string `json:"pass"`
}

// loadConfig reads path into a fileConfig. An empty path is a no-op.
func loadConfig(path string) (*fileConfig, error) {
	if path == "" {
		return &fileConfig{}, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("wotserver: config: %w", err)
	}
	var c fileConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("wotserver: config %s: %w", path, err)
	}
	return &c, nil
}

// apply fills any flag the file sets and the command line did not.
// set reports whether a flag was given explicitly.
func (c *fileConfig) apply(set func(name string) bool) {
	str := func(name string, dst *string, v *string) {
		if v != nil && !set(name) {
			*dst = *v
		}
	}
	num := func(name string, dst *int64, v *int64) {
		if v != nil && !set(name) {
			*dst = *v
		}
	}
	boolean := func(name string, dst *bool, v *bool) {
		if v != nil && !set(name) {
			*dst = *v
		}
	}
	str("addr", flagAddr, c.Addr)
	str("privkey", flagPrivKey, c.PrivKey)
	str("s1", flagS1, c.S1)
	str("s2", flagS2, c.S2)
	str("flood", flagFlood, c.Flood)
	str("floodkey", flagFloodKey, c.FloodKey)
	str("floodflow", flagFloodFlow, c.FloodFlow)
	str("post", flagPost, c.Post)
	str("postkey", flagPostKey, c.PostKey)
	str("postflow", flagPostFlow, c.PostFlow)
	str("defs", flagDefs, c.Defs)
	str("baseapp", flagBaseApp, c.BaseApp)
	num("maxnonce", flagMaxNonce, c.MaxNonce)
	boolean("any-version", flagAnyVersion, c.AnyVersion)
	str("digest", flagDigest, c.Digest)
	boolean("verbose", flagVerbose, c.Verbose)
	str("db", flagDB, c.DB)
	str("user", flagUser, c.User)
	str("pass", flagPass, c.Pass)
}
