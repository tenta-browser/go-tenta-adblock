package ublock

import (
	"net/http"
	"time"
)

type ProfileType uint8

const (
	ProfileTypeUnknown ProfileType = iota
	ProfileTypeEssential
	ProfileTypeBalanced
	ProfileTypeStrict
)

func ParseProfileType(s string) ProfileType {
	switch s {
	case "essential":
		return ProfileTypeEssential
	case "balanced":
		return ProfileTypeBalanced
	case "strict":
		return ProfileTypeStrict
	}

	return ProfileTypeUnknown
}

func (p ProfileType) String() string {
	switch p {
	case ProfileTypeEssential:
		return "essential"
	case ProfileTypeBalanced:
		return "balanced"
	case ProfileTypeStrict:
		return "strict"
	}

	return "unknown"
}

// NOTE
// Profiles use a different logic:
// `assetsUrl` is the most restrictive list (strict), and
// `ListUrlBalanced` and `ListUrlEssential` are lists containing
// exceptions for the rules found in `assetUrl`.
type Config struct {
	CompileDebugAsset bool          // use debug assets when building non-iOS filters
	CacheValidity     time.Duration // TTL for cached files on disk
	IOSFilterCutoffNo uint32        // the number of rules that can fit into one JSON
	HttpClient        *http.Client  // HTTP client used to download all assets
	Profile           ProfileType   // how aggressive the d.a.w.g. filter should be
	ListUrlBalanced   string        // list containing the exceptions for the balanced profile
	ListUrlEssential  string        // list containing the exceptions for the essential profile
	assetsUrl         string        // asset list's URL
	isCustomUrl       bool          // indicates if the assetsUrl is a custom URL or the default one (from uBlock)
}

// sets a custom asset URL
func (c *Config) SetCustomUrl(url string) {
	c.isCustomUrl = true
	c.assetsUrl = url
}

func (c *Config) SetAssetsUrl(url string) {
	c.isCustomUrl = false
	c.assetsUrl = url
}

func DefaultConfig() *Config {
	return &Config{
		CompileDebugAsset: false,
		CacheValidity:     24 * time.Hour,
		IOSFilterCutoffNo: 40000, // it's probably 30k, but safety first -- the number of rules that can fit into one JSON
		HttpClient:        http.DefaultClient,
		Profile:           ProfileTypeStrict,
		ListUrlBalanced:   "https://update.avastbrowser.com/adblock/filterlist.txt",
		ListUrlEssential:  "https://easylist-downloads.adblockplus.org/exceptionrules.txt",
		assetsUrl:         "https://raw.githubusercontent.com/gorhill/uBlock/master/assets/assets.json",
	}
}
