package quicadmission

// RetainBoundToken releases unused tokens from a single-connection wire4 pool.
// It never revokes another batch or subject, and refuses a token outside it.
func (s *Store) RetainBoundToken(subject string, tokens []Token, keep Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	for _, token := range tokens {
		if token == keep {
			found = true
			break
		}
	}
	selected := s.lookup(keep)
	if !found || selected == nil || !selected.bound || selected.subject != subject {
		return ErrRejected
	}
	for _, token := range tokens {
		if token == keep {
			continue
		}
		e := s.lookup(token)
		if e != nil && e.bound && e.subject == subject {
			s.drop(e)
		}
	}
	return nil
}
