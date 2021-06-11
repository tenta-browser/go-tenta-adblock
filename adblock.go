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
)

var (
	cache       *assetCache
	cfg         *Config
	initialized = false
)

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
	if assetList, err = constructAssetList(cache, forIOS, cfg); err != nil {
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
