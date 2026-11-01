package server

import (
	"fmt"

	"github.com/LockBlock-dev/wot/lobby"
)

// BundleBuilder composes a lobby bundle from documents built in code,
// instead of patching a captured stream.
//
// The flood is a sequence of proto-2 documents (see DecodeBundle): the
// static lobby config first, then the per-account document. A builder
// holds those documents as node trees and serialises them in order, so a
// bundle can be generated rather than replayed.
//
//	raw, err := NewBundle().
//		Document(configDoc).
//		Document(accountDoc).
//		Encode()
type BundleBuilder struct {
	docs [][]*lobby.FNode
}

// NewBundle returns an empty builder.
func NewBundle() *BundleBuilder { return &BundleBuilder{} }

// Document appends one pickle document: the nodes it carries, in order.
//
// The lobby's outer dict is never closed on the wire, so a document is a
// stack of nodes rather than one root value.
func (b *BundleBuilder) Document(nodes ...*lobby.FNode) *BundleBuilder {
	b.docs = append(b.docs, nodes)
	return b
}

// Documents reports how many documents have been added.
func (b *BundleBuilder) Documents() int { return len(b.docs) }

// Encode serialises every document, in order, into one bundle stream.
func (b *BundleBuilder) Encode() ([]byte, error) {
	if len(b.docs) == 0 {
		return nil, fmt.Errorf("server: bundle builder: no documents")
	}
	var out []byte
	for i, nodes := range b.docs {
		raw, err := lobby.EncodeDocument(nodes...)
		if err != nil {
			return nil, fmt.Errorf("server: bundle builder: document %d: %w", i, err)
		}
		out = append(out, raw...)
	}
	return out, nil
}

// BuildBundle is the one-shot form of BundleBuilder.
func BuildBundle(docs ...[]*lobby.FNode) ([]byte, error) {
	b := NewBundle()
	for _, d := range docs {
		b.Document(d...)
	}
	return b.Encode()
}

// FromCapture seeds a builder from a captured bundle, so a generated
// bundle can start from the real config and replace only what it means
// to.
//
// The documents are decoded, not copied: the result is re-encoded
// canonically, so it will not be byte-identical to the capture, and the
// capture's non-pickle tail (the channel-framed packets that follow the
// pickle) is not carried over — a rebuilt bundle is the documents only.
func FromCapture(raw []byte) (*BundleBuilder, error) {
	b, err := DecodeBundle(raw)
	if err != nil {
		return nil, err
	}
	out := NewBundle()
	for _, d := range b.Docs {
		out.Document(d.Stack...)
	}
	return out, nil
}
