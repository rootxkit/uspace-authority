package ridpipe

import "container/list"

// lru is a map bounded to max entries (E-10): putting a new key at the
// bound drops the least recently used one and reports it. Not safe for
// concurrent use; the Pipeline holds its lock.
type lru[K comparable, V any] struct {
	max   int
	items map[K]*list.Element
	order *list.List // front = most recently used
}

type lruEntry[K comparable, V any] struct {
	key K
	val V
}

func newLRU[K comparable, V any](maxEntries int) *lru[K, V] {
	return &lru[K, V]{max: max(1, maxEntries), items: make(map[K]*list.Element), order: list.New()}
}

// get returns the value of k and marks it used.
func (l *lru[K, V]) get(k K) (V, bool) {
	if el, ok := l.items[k]; ok {
		l.order.MoveToFront(el)
		return el.Value.(*lruEntry[K, V]).val, true
	}
	var zero V
	return zero, false
}

// put sets k to v and reports whether another key was evicted to make
// room.
func (l *lru[K, V]) put(k K, v V) (evicted bool) {
	if el, ok := l.items[k]; ok {
		el.Value.(*lruEntry[K, V]).val = v
		l.order.MoveToFront(el)
		return false
	}
	if len(l.items) >= l.max {
		if back := l.order.Back(); back != nil {
			delete(l.items, back.Value.(*lruEntry[K, V]).key)
			l.order.Remove(back)
			evicted = true
		}
	}
	l.items[k] = l.order.PushFront(&lruEntry[K, V]{key: k, val: v})
	return evicted
}

// take returns the value of k and removes it.
func (l *lru[K, V]) take(k K) (V, bool) {
	el, ok := l.items[k]
	if !ok {
		var zero V
		return zero, false
	}
	delete(l.items, k)
	l.order.Remove(el)
	return el.Value.(*lruEntry[K, V]).val, true
}

func (l *lru[K, V]) len() int { return len(l.items) }
