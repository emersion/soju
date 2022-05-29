package xirc

type CapRegistry struct {
	Available map[string]string
	Enabled   map[string]struct{}
}

func NewCapRegistry() CapRegistry {
	return CapRegistry{
		Available: make(map[string]string),
		Enabled:   make(map[string]struct{}),
	}
}

func (cr *CapRegistry) IsAvailable(name string) bool {
	_, ok := cr.Available[name]
	return ok
}

func (cr *CapRegistry) IsEnabled(name string) bool {
	_, ok := cr.Enabled[name]
	return ok
}

func (cr *CapRegistry) Del(name string) {
	delete(cr.Available, name)
	delete(cr.Enabled, name)
}

func (cr *CapRegistry) SetEnabled(name string, enabled bool) {
	if enabled {
		cr.Enabled[name] = struct{}{}
	} else {
		delete(cr.Enabled, name)
	}
}
