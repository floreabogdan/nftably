package render

import "encoding/json"

// DecodeParams turns a statement's stored JSON params into the string map the
// catalogue's render functions expect. A blank or malformed blob yields an
// empty map, so a verdict with no params (the common case) just works. Exported
// so the web layer can rehydrate a saved statement into its form fields.
func DecodeParams(s string) map[string]string {
	out := map[string]string{}
	if s == "" {
		return out
	}
	_ = json.Unmarshal([]byte(s), &out)
	return out
}


// EncodeParams is the inverse, for the web layer building a statement from a
// form. Empty maps encode as "{}".
func EncodeParams(p map[string]string) string {
	if len(p) == 0 {
		return "{}"
	}
	b, err := json.Marshal(p)
	if err != nil {
		return "{}"
	}
	return string(b)
}
