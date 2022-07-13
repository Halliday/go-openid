package openid

import "strings"

type Scopes []string

func NewScopes(s string) Scopes {
	if s == "" {
		return nil
	}
	return Scopes(strings.Split(s, " "))
}

func (scopes *Scopes) Add(scope string) bool {
	if !scopes.Has(scope) {
		*scopes = append(*scopes, scope)
		return true
	}
	return false
}

func (scopes Scopes) Has(scope string) bool {
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

func (scopes Scopes) String() string {
	if scopes == nil {
		return ""
	}
	return strings.Join(scopes, " ")
}

func (scopes *Scopes) Del(scope string) bool {
	for i, s := range *scopes {
		if s == scope {
			copy((*scopes)[i:], (*scopes)[i+1:])
			return true
		}
	}
	return false
}
