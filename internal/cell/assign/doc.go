// Package assign is api's writer of the cell ownership map (PUT
// /v1/cells, admin): the map is written into KV bucket cells inside the
// transaction of its events row, under an advisory lock, with the next
// version; a map the bucket cannot take is refused (503, nothing
// recorded) and one past the bucket's value bound is refused naming it
// (E-10). It links the relational store, so only api imports it; the
// workers read the map through internal/cell.
package assign
