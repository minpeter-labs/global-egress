// Package georoute provides a coarse geographic prior for choosing which entry
// tunnel should serve which exit.
//
// The prior only matters until real measurements exist. Every request through an
// entry produces a latency sample, and measured samples always win; this package
// just avoids a cold start where a European exit is reached through a tunnel on
// the other side of the planet.
package georoute

import "strings"

// Region is a coarse geographic bucket.
type Region string

// The buckets. Deliberately coarse: finer granularity would pretend to a
// precision that a country-code lookup cannot deliver.
const (
	Unknown      Region = ""
	EastAsia     Region = "east-asia"
	SouthAsia    Region = "south-asia"
	Oceania      Region = "oceania"
	Europe       Region = "europe"
	MiddleEast   Region = "middle-east"
	Africa       Region = "africa"
	NorthAmerica Region = "north-america"
	SouthAmerica Region = "south-america"
)

// countryRegion maps the country codes the provider operates in.
var countryRegion = map[string]Region{
	// East and South-East Asia
	"jp": EastAsia, "hk": EastAsia, "tw": EastAsia, "kr": EastAsia,
	"sg": SouthAsia, "my": SouthAsia, "th": SouthAsia, "id": SouthAsia,
	"ph": SouthAsia, "vn": SouthAsia, "in": SouthAsia,
	// Oceania
	"au": Oceania, "nz": Oceania,
	// Europe
	"al": Europe, "at": Europe, "be": Europe, "bg": Europe, "ch": Europe,
	"cy": Europe, "cz": Europe, "de": Europe, "dk": Europe, "ee": Europe,
	"es": Europe, "fi": Europe, "fr": Europe, "gb": Europe, "gr": Europe,
	"hr": Europe, "hu": Europe, "ie": Europe, "it": Europe, "lt": Europe,
	"lu": Europe, "lv": Europe, "md": Europe, "nl": Europe, "no": Europe,
	"pl": Europe, "pt": Europe, "ro": Europe, "rs": Europe, "se": Europe,
	"si": Europe, "sk": Europe, "ua": Europe,
	// Middle East
	"il": MiddleEast, "tr": MiddleEast, "ae": MiddleEast,
	// Africa
	"za": Africa, "ng": Africa, "ke": Africa,
	// Americas
	"us": NorthAmerica, "ca": NorthAmerica, "mx": NorthAmerica,
	"ar": SouthAmerica, "br": SouthAmerica, "cl": SouthAmerica,
	"co": SouthAmerica, "pe": SouthAmerica,
}

// RegionOf returns the region of a country code, or Unknown.
func RegionOf(country string) Region {
	return countryRegion[strings.ToLower(strings.TrimSpace(country))]
}

// distance is a unitless hop cost between regions. Only the ordering matters.
var distance = map[Region]map[Region]int{
	EastAsia:     {EastAsia: 0, SouthAsia: 1, Oceania: 2, NorthAmerica: 3, MiddleEast: 4, Europe: 5, SouthAmerica: 6, Africa: 6},
	SouthAsia:    {SouthAsia: 0, EastAsia: 1, Oceania: 2, MiddleEast: 3, Europe: 4, NorthAmerica: 4, Africa: 5, SouthAmerica: 7},
	Oceania:      {Oceania: 0, EastAsia: 2, SouthAsia: 2, NorthAmerica: 4, Europe: 6, MiddleEast: 6, SouthAmerica: 6, Africa: 7},
	Europe:       {Europe: 0, MiddleEast: 1, Africa: 2, NorthAmerica: 3, SouthAsia: 4, EastAsia: 5, SouthAmerica: 5, Oceania: 6},
	MiddleEast:   {MiddleEast: 0, Europe: 1, Africa: 2, SouthAsia: 3, EastAsia: 4, NorthAmerica: 4, SouthAmerica: 6, Oceania: 6},
	Africa:       {Africa: 0, Europe: 2, MiddleEast: 2, SouthAsia: 5, NorthAmerica: 5, SouthAmerica: 5, EastAsia: 6, Oceania: 7},
	NorthAmerica: {NorthAmerica: 0, SouthAmerica: 2, Europe: 3, EastAsia: 3, SouthAsia: 4, Oceania: 4, MiddleEast: 4, Africa: 5},
	SouthAmerica: {SouthAmerica: 0, NorthAmerica: 2, Europe: 5, Africa: 5, MiddleEast: 6, EastAsia: 6, SouthAsia: 7, Oceania: 6},
}

// unknownCost is used whenever either side cannot be classified. It sits in the
// middle of the scale so an unknown pairing is neither preferred nor excluded.
const unknownCost = 4

// Cost returns the prior cost of reaching an exit country through an entry
// country. Lower is better.
func Cost(entryCountry, exitCountry string) int {
	from, to := RegionOf(entryCountry), RegionOf(exitCountry)
	if from == Unknown || to == Unknown {
		return unknownCost
	}
	if row, ok := distance[from]; ok {
		if cost, ok := row[to]; ok {
			return cost
		}
	}
	return unknownCost
}
