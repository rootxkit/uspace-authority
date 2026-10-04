package registry

import (
	"context"
	"errors"
)

// ErrAmbiguous is a lookup that matched more than one registration.
var ErrAmbiguous = errors.New("more than one registration matches")

// OperatorByNumber finds the operator a registration number names, on
// its compare key under the active pattern (G-04); found is false when
// none does, and ErrAmbiguous is returned when two do (WP-19's police
// lookups; the number's secret part never reaches the answer).
func (s *Service) OperatorByNumber(ctx context.Context, number string) (Operator, bool, error) {
	ops, err := s.ListOperators(ctx, number, "", Page{Limit: 2})
	if err != nil {
		return Operator{}, false, err
	}
	switch len(ops) {
	case 0:
		return Operator{}, false, nil
	case 1:
		return ops[0], true, nil
	}
	return Operator{}, false, ErrAmbiguous
}

// UASBySerial finds the aircraft a serial names with uspace-core's own
// matching (exact, else a unique folded match; G-05, G-12), as F8 does.
func (s *Service) UASBySerial(ctx context.Context, sn string) (UAS, bool, error) {
	return s.lookupSerial(ctx, sn)
}
