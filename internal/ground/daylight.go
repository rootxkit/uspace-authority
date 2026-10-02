package ground

import "github.com/rootxkit/uspace-core/ed318"

// Daylight resolves ED-318's daylight events (BMCT, SR, SS, EECT) for
// ed318.Applies and ed318.ToZones from a position and a date. It is
// uspace-core's ed318.NOAADaylight, never a second implementation here
// (CLAUDE.md rule 3): the NOAA Solar Calculator algorithm after Meeus,
// "Astronomical Algorithms", sunrise and sunset at a solar zenith of
// 90.833 degrees and civil twilight at 96 degrees; NOAA states it is
// within one minute between 72 degrees north and south. Where the sun
// does not reach an event's altitude that day it returns an error
// wrapping ed318.ErrNoEvent, and the zone is not evaluated.
//
// daylight_test.go checks it at Tbilisi on two dates against published
// times (sunrise-sunset.org).
func Daylight() ed318.Daylight { return ed318.NOAADaylight{} }
