package xirc

func casemapASCII(name string) string {
	nameBytes := []byte(name)
	for i, r := range nameBytes {
		if 'A' <= r && r <= 'Z' {
			nameBytes[i] = r + 'a' - 'A'
		}
	}
	return string(nameBytes)
}

func casemapRFC1459(name string) string {
	nameBytes := []byte(name)
	for i, r := range nameBytes {
		if 'A' <= r && r <= 'Z' {
			nameBytes[i] = r + 'a' - 'A'
		} else if r == '{' {
			nameBytes[i] = '['
		} else if r == '}' {
			nameBytes[i] = ']'
		} else if r == '\\' {
			nameBytes[i] = '|'
		} else if r == '~' {
			nameBytes[i] = '^'
		}
	}
	return string(nameBytes)
}

func casemapRFC1459Strict(name string) string {
	nameBytes := []byte(name)
	for i, r := range nameBytes {
		if 'A' <= r && r <= 'Z' {
			nameBytes[i] = r + 'a' - 'A'
		} else if r == '{' {
			nameBytes[i] = '['
		} else if r == '}' {
			nameBytes[i] = ']'
		} else if r == '\\' {
			nameBytes[i] = '|'
		}
	}
	return string(nameBytes)
}

// CaseMapping returns the canonical representation of a name according to an
// IRC case-mapping.
type CaseMapping func(string) string

var (
	CaseMappingASCII         CaseMapping = casemapASCII
	CaseMappingRFC1459       CaseMapping = casemapRFC1459
	CaseMappingRFC1459Strict CaseMapping = casemapRFC1459Strict
)

func ParseCaseMapping(s string) CaseMapping {
	var cm CaseMapping
	switch s {
	case "ascii":
		cm = CaseMappingASCII
	case "rfc1459":
		cm = CaseMappingRFC1459
	case "rfc1459-strict":
		cm = CaseMappingRFC1459Strict
	}
	return cm
}

type CaseMappingMap[V interface{}] struct {
	m       map[string]caseMappingEntry[V]
	casemap CaseMapping
}

type caseMappingEntry[V interface{}] struct {
	originalKey string
	value       V
}

func NewCaseMappingMap[V interface{}](cm CaseMapping) CaseMappingMap[V] {
	return CaseMappingMap[V]{
		m:       make(map[string]caseMappingEntry[V]),
		casemap: cm,
	}
}

func (cmm *CaseMappingMap[V]) Has(name string) bool {
	_, ok := cmm.m[cmm.casemap(name)]
	return ok
}

func (cmm *CaseMappingMap[V]) Len() int {
	return len(cmm.m)
}

func (cmm *CaseMappingMap[V]) Get(name string) V {
	entry, ok := cmm.m[cmm.casemap(name)]
	if !ok {
		var v V
		return v
	}
	return entry.value
}

func (cmm *CaseMappingMap[V]) Set(name string, value V) {
	nameCM := cmm.casemap(name)
	entry, ok := cmm.m[nameCM]
	if !ok {
		cmm.m[nameCM] = caseMappingEntry[V]{
			originalKey: name,
			value:       value,
		}
		return
	}
	entry.value = value
	cmm.m[nameCM] = entry
}

func (cmm *CaseMappingMap[V]) Del(name string) {
	delete(cmm.m, cmm.casemap(name))
}

func (cmm *CaseMappingMap[V]) ForEach(f func(string, V)) {
	for _, entry := range cmm.m {
		f(entry.originalKey, entry.value)
	}
}

func (cmm *CaseMappingMap[V]) SetCaseMapping(newCasemap CaseMapping) {
	cmm.casemap = newCasemap
	m := make(map[string]caseMappingEntry[V], len(cmm.m))
	for _, entry := range cmm.m {
		m[cmm.casemap(entry.originalKey)] = entry
	}
	cmm.m = m
}
