package cisp

import "slices"

// Dataset is a CIS dataset (the CISP's api/openapi.yaml, pinned in
// api/clients/cisp.yaml).
type Dataset string

// The CIS datasets.
const (
	DatasetZones        Dataset = "zones"
	DatasetUSpace       Dataset = "uspace_airspace"
	DatasetUSSPList     Dataset = "ussp_list"
	DatasetRestrictions Dataset = "restrictions"
)

// PublishDatasets are the datasets the authority publishes (F1).
var PublishDatasets = []Dataset{DatasetZones, DatasetUSpace, DatasetUSSPList}

// SubscribedDatasets are the datasets the authority subscribes to and
// caches (F3): its own publications, read back, and the ANSP's
// restrictions.
var SubscribedDatasets = []Dataset{DatasetZones, DatasetUSpace, DatasetUSSPList, DatasetRestrictions}

// ParseDataset reads a dataset name.
func ParseDataset(s string) (Dataset, bool) {
	d := Dataset(s)
	return d, slices.Contains(SubscribedDatasets, d)
}

// ED318 is true for the datasets that are ED-318 FeatureCollections.
func (d Dataset) ED318() bool { return d != DatasetUSSPList }

// Publishable is true for the datasets the authority publishes.
func (d Dataset) Publishable() bool { return slices.Contains(PublishDatasets, d) }

// ContentType is the media type a publication of d is sent as.
func (d Dataset) ContentType() string {
	if d == DatasetUSSPList {
		return "application/json"
	}
	return "application/geo+json"
}

// Scopes of the CIS (WP-2 table B).
const (
	ScopeRead = "cis.read"
)

// PublishScope is the scope that publishes d (WP-2 table B): the
// U-space dataset's scope is cis.publish:uspace.
func (d Dataset) PublishScope() string {
	switch d {
	case DatasetUSpace:
		return "cis.publish:uspace"
	case DatasetZones, DatasetUSSPList, DatasetRestrictions:
		return "cis.publish:" + string(d)
	}
	return ""
}

// The publishers whose signatures a pulled version must carry (the
// CISP's publisher of each dataset): the authority for its own F1
// datasets, the ANSP for the restrictions (F2).
const (
	PublisherAuthority = "authority"
	PublisherANSP      = "ansp"
)

// PublisherOf is the publisher whose key must have signed a version of d.
func PublisherOf(d Dataset) string {
	if d == DatasetRestrictions {
		return PublisherANSP
	}
	return PublisherAuthority
}
