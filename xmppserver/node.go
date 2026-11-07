package xmppserver

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// Node is one parsed XML element: its name, attributes, children and
// character data.
//
// XMPP stanzas are small and shallow, so a generic tree keeps the
// handlers readable and lets one decoder serve every namespace the
// client uses (roster, blocking, disco, MUC, the WG extensions). The
// alternative — a struct per stanza — would need a new type for every
// extension the client sends, and the client sends extensions we only
// need to echo back.
type Node struct {
	Name     xml.Name
	Attrs    []xml.Attr
	Children []*Node
	Text     string
}

// Attr returns the value of an unqualified attribute, or "".
func (n *Node) Attr(name string) string {
	if n == nil {
		return ""
	}
	for _, a := range n.Attrs {
		if a.Name.Local == name && a.Name.Space == "" {
			return a.Value
		}
	}
	return ""
}

// Child returns the first child with the given local name in namespace
// space, or nil. An empty space matches any namespace.
func (n *Node) Child(space, local string) *Node {
	if n == nil {
		return nil
	}
	for _, c := range n.Children {
		if c.Name.Local != local {
			continue
		}
		if space == "" || c.Name.Space == space {
			return c
		}
	}
	return nil
}

// ChildrenNamed returns every child with the given local name.
func (n *Node) ChildrenNamed(local string) []*Node {
	if n == nil {
		return nil
	}
	var out []*Node
	for _, c := range n.Children {
		if c.Name.Local == local {
			out = append(out, c)
		}
	}
	return out
}

// TextOf returns the character data of the first matching child, or "".
func (n *Node) TextOf(space, local string) string {
	if c := n.Child(space, local); c != nil {
		return c.Text
	}
	return ""
}

// readElement consumes tokens from dec until the element that starts at
// start is closed, and returns the tree.
//
// This is what makes an XMPP stream readable with encoding/xml: the
// stream's root element is never closed while the session lives, so the
// caller reads the root StartElement itself and then hands every
// following StartElement here.
func readElement(dec *xml.Decoder, start xml.StartElement) (*Node, error) {
	n := &Node{Name: start.Name, Attrs: start.Attr}
	var text strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			child, err := readElement(dec, t)
			if err != nil {
				return nil, err
			}
			n.Children = append(n.Children, child)
		case xml.EndElement:
			n.Text = strings.TrimSpace(text.String())
			return n, nil
		case xml.CharData:
			text.Write(t)
		}
	}
}

// nextElement reads tokens until the next StartElement, skipping the
// XML declaration, comments and whitespace. It returns io.EOF when the
// peer closed the stream.
func nextElement(dec *xml.Decoder) (xml.StartElement, error) {
	for {
		tok, err := dec.Token()
		if err != nil {
			return xml.StartElement{}, err
		}
		if start, ok := tok.(xml.StartElement); ok {
			return start, nil
		}
	}
}

// escAttr escapes an XML attribute value.
func escAttr(s string) string {
	r := strings.NewReplacer(`&`, "&amp;", `<`, "&lt;", `>`, "&gt;", `"`, "&quot;", `'`, "&apos;")
	return r.Replace(s)
}

// escText escapes XML character data.
func escText(s string) string {
	r := strings.NewReplacer(`&`, "&amp;", `<`, "&lt;", `>`, "&gt;")
	return r.Replace(s)
}

// tag renders one element with attributes and pre-rendered inner XML.
// An empty inner renders a self-closing element, which is what the
// client's own builders emit for empty extensions.
func tag(name string, attrs [][2]string, inner string) string {
	var sb strings.Builder
	sb.WriteByte('<')
	sb.WriteString(name)
	for _, a := range attrs {
		if a[1] == "" {
			continue
		}
		fmt.Fprintf(&sb, ` %s="%s"`, a[0], escAttr(a[1]))
	}
	if inner == "" {
		sb.WriteString("/>")
		return sb.String()
	}
	sb.WriteString(">")
	sb.WriteString(inner)
	sb.WriteString("</")
	sb.WriteString(name)
	sb.WriteString(">")
	return sb.String()
}

// textTag renders an element whose only content is escaped text.
func textTag(name, text string) string {
	if text == "" {
		return tag(name, nil, "")
	}
	return tag(name, nil, escText(text))
}

// readAll is a helper for tests and for the stream-open path: it reads
// one element from r and returns its tree.
func readAll(r io.Reader) (*Node, error) {
	dec := xml.NewDecoder(r)
	start, err := nextElement(dec)
	if err != nil {
		return nil, err
	}
	return readElement(dec, start)
}
