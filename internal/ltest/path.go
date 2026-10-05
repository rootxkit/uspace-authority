package ltest

import (
	"math"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geodesy"
	"github.com/rootxkit/uspace-core/odid"
)

// Point is a position and an altitude above mean sea level.
type Point struct {
	LatDeg, LonDeg, AltAMSLM float64
}

// At is the point p at altitude altAMSLM.
func At(latDeg, lonDeg, altAMSLM float64) Point {
	return Point{LatDeg: latDeg, LonDeg: lonDeg, AltAMSLM: altAMSLM}
}

// Leg is part of a path: Steps steps from From to To (a hover when they
// are equal), the last step at To.
type Leg struct {
	Steps    int
	From, To Point
	// Status is the leg's operational status (airborne when zero).
	Status odid.Status
	// Silent legs transmit nothing.
	Silent bool
}

// Stay is a leg of n steps at p.
func Stay(n int, p Point) Leg { return Leg{Steps: n, From: p, To: p} }

// Move is a leg of n steps from a to b.
func Move(n int, a, b Point) Leg { return Leg{Steps: n, From: a, To: b} }

// Landed is a leg of n steps at p on the ground (ODID status ground).
func Landed(n int, p Point) Leg { return Leg{Steps: n, From: p, To: p, Status: odid.StatusGround} }

// Quiet is a leg of n steps with nothing transmitted.
func Quiet(n int, p Point) Leg { return Leg{Steps: n, From: p, To: p, Silent: true} }

// Legs is the path through legs in order; after the last it stays at the
// last leg's end (and status). Speed and track are those of each step's
// own move, through uspace-core geodesy, so the broadcast is consistent
// with the positions.
func Legs(legs ...Leg) Path {
	return func(step int) State {
		k := step
		for i, l := range legs {
			if k < l.Steps || i == len(legs)-1 {
				n := max(l.Steps, 1)
				f := math.Min(float64(k+1)/float64(n), 1)
				prev := math.Min(float64(k)/float64(n), 1)
				p := lerp(l.From, l.To, f)
				q := lerp(l.From, l.To, prev)
				st := State{LatDeg: p.LatDeg, LonDeg: p.LonDeg, AltAMSLM: p.AltAMSLM, Status: l.Status, Silent: l.Silent}
				if st.Status == 0 {
					st.Status = odid.StatusAirborne
				}
				if k < l.Steps {
					a, b := core.LatLon{LatDeg: q.LatDeg, LonDeg: q.LonDeg}, core.LatLon{LatDeg: p.LatDeg, LonDeg: p.LonDeg}
					if d, bearing, _, err := geodesy.Inverse(a, b); err == nil && d > 0 {
						st.SpeedMS = d
						st.TrackDeg = math.Mod(bearing+360, 360)
						if st.TrackDeg >= 359.5 {
							st.TrackDeg = 0
						}
					}
				}
				return st
			}
			k -= l.Steps
		}
		return State{Silent: true}
	}
}

func lerp(a, b Point, f float64) Point {
	return Point{LatDeg: a.LatDeg + (b.LatDeg-a.LatDeg)*f, LonDeg: a.LonDeg + (b.LonDeg-a.LonDeg)*f, AltAMSLM: a.AltAMSLM + (b.AltAMSLM-a.AltAMSLM)*f}
}

// Steps is the total of legs' steps.
func Steps(legs ...Leg) int {
	n := 0
	for _, l := range legs {
		n += l.Steps
	}
	return n
}
