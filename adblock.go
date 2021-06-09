/**
 * Go uBlock
 *
 *    Copyright 2021 Tenta, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * For any questions, please contact developer@tenta.io
 */

package ublock

import (
	"fmt"
	"net/http"
	"time"
)

var (
	cache       *assetCache
	cfg         *Config
	initialized = false
)

type Config struct {
	CompileDebugAsset bool          // use debug assets when building non-iOS filters
	CacheValidity     time.Duration // TTL for cached files on disk
	IOSFilterCutoffNo uint32        // the number of rules that can fit into one JSON
	HttpClient        *http.Client  // HTTP client used to download all assets
	assetsUrl         string        // asset list's URL
	isCustomUrl       bool          // indicates if the assetsUrl is a custom URL or the default one (from uBlock)
}

// sets a custom asset URL
func (c *Config) SetCustomUrl(url string) {
	c.isCustomUrl = true
	c.assetsUrl = url
}

func DefaultConfig() *Config {
	return &Config{
		CompileDebugAsset: false,
		CacheValidity:     24 * time.Hour,
		IOSFilterCutoffNo: 40000, // it's probably 30k, but safety first -- the number of rules that can fit into one JSON
		HttpClient:        http.DefaultClient,
		assetsUrl:         "https://raw.githubusercontent.com/gorhill/uBlock/master/assets/assets.json",
	}
}

// Init - initialize for the export side of operations
//
// filterCacheDir	: directory where assets are cached
// cfg				: configuration options
func Init(filterCacheDir string, c *Config) (err error) {
	if filterCacheDir == "" {
		return fmt.Errorf("unable to work with empty files or directories")
	}

	if initialized {
		return fmt.Errorf("already initialized")
	}

	cache, err = newAssetCache(filterCacheDir, c.CacheValidity)
	if err != nil {
		return fmt.Errorf("cache build error: %s", err)
	}

	cfg = c
	initialized = true
	return nil
}

// Build - constructs new filters
//
// outputPath		: path and filename for the new filter
// forIOS			: toggles between d.a.w.g. (android) or JSON (iOS) format
func Build(outputPath string, forIOS bool) (err error) {
	if outputPath == "" {
		return fmt.Errorf("unable to work with empty files or directories")
	}

	if !initialized {
		return fmt.Errorf("package not initialized")
	}

	// download and build the ruleset list
	var assetList []*assetListItem
	if assetList, err = constructAssetList(cfg.HttpClient, cache, cfg.assetsUrl, cfg.isCustomUrl, forIOS); err != nil {
		return err
	}

	// build filters
	if !forIOS {
		_, err = constructFilter(cfg.HttpClient, cache, outputPath, assetList, cfg.CompileDebugAsset)
	} else {
		err = constructFilterJSON(cfg.HttpClient, cache, outputPath, assetList, int(cfg.IOSFilterCutoffNo))
	}

	return
}
