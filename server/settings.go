package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/LockBlock-dev/wot/lobby"
)

// SettingsFromJSON reads the lobby's server-settings document from a JSON
// file and returns its pickle, ready for login.BaseAppConfig.Settings.
//
// The document is the `initialServerSettings` dict the client's
// ServerSettings.set() reads: every key it knows is looked up with an
// `if key in settings` guard, so a partial document is valid and the
// client falls back to its own defaults for the rest. The keys that are
// read through the schema manager (getConfigModel) are the exception —
// those must be present, even as an empty object, or the client raises.
//
// JSON maps to the pickle types the client expects: objects to dicts,
// arrays to lists, numbers to ints (or floats when they have a fraction),
// strings to str, booleans to bool, null to None.
func SettingsFromJSON(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("server: settings %s: %w", path, err)
	}
	obj, ok := doc.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("server: settings %s: top level must be an object", path)
	}
	node, err := jsonNode(obj)
	if err != nil {
		return nil, fmt.Errorf("server: settings %s: %w", path, err)
	}
	out, err := lobby.EncodeDocument(node)
	if err != nil {
		return nil, fmt.Errorf("server: settings %s: %w", path, err)
	}
	return out, nil
}

// SettingsSubsetFromJSON is SettingsFromJSON restricted to the named keys.
//
// `initialServerSettings` rides the Account entity, so it has to fit one
// packet — the full document is ~4.5 KB and the bundle payload is ~1.2 KB. The
// client reads every key with an `if key in settings` guard and falls back to
// its own default, so a subset is a valid lobby; the keys that must be present
// are the ones it reads through the schema manager, plus any this server has to
// force (dog tags off, or `Avatar.setClientReady` throws and the battle is
// inert). A key that is absent from the document is written as an empty object.
func SettingsSubsetFromJSON(path string, keys []string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("server: settings %s: %w", path, err)
	}
	sub := make(map[string]any, len(keys))
	for _, k := range keys {
		if v, ok := doc[k]; ok {
			sub[k] = v
			continue
		}
		sub[k] = map[string]any{}
	}
	node, err := jsonNode(sub)
	if err != nil {
		return nil, fmt.Errorf("server: settings %s: %w", path, err)
	}
	return lobby.EncodeDocument(node)
}

// jsonNode converts one decoded JSON value into a pickle node.
func jsonNode(v any) (*lobby.FNode, error) {
	switch x := v.(type) {
	case nil:
		return lobby.NewNone(), nil
	case bool:
		return lobby.NewBool(x), nil
	case string:
		return lobby.NewString(x), nil
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return lobby.NewInt(i), nil
		}
		f, err := x.Float64()
		if err != nil {
			return nil, fmt.Errorf("bad number %q", x)
		}
		return lobby.NewFloat(f), nil
	case []any:
		list := lobby.NewList()
		for _, item := range x {
			n, err := jsonNode(item)
			if err != nil {
				return nil, err
			}
			list.Append(n)
		}
		return list, nil
	case map[string]any:
		dict := lobby.NewDict()
		for k, item := range x {
			n, err := jsonNode(item)
			if err != nil {
				return nil, err
			}
			dict.Set(k, n)
		}
		return dict, nil
	}
	return nil, fmt.Errorf("unsupported JSON value %T", v)
}
