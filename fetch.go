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
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

// ASSETS
//
// An asset is a list of resources that
// must be blocked/hidden in a webpage

type assetItem struct {
	Content, Title, SupportURL, Group string
	ContentURL                        interface{}
	UpdateAfter                       float64
	Off                               bool
}

type assetListItem struct {
	name, content, group, contentURL string
}

// download stats
var downloadedBytes, readBytes int64

/// fetches (cache/network) a filter file
func fetchText(hc *http.Client, as *assetCache, url string) (string, error) {
	h := md5.New()
	h.Write([]byte(url))

	if content, err := as.get(url); err != nil {
		return "", fmt.Errorf("get cache asset error [%s]", err)
	} else if content != nil {
		log("Returning from cache for [%s].\n", url)
		readBytes += int64(len(content))
		return string(content), nil
	}

	log("Downloading asset for [%s].\n", url)
	r, e := hc.Get(url)
	if e != nil {
		return "", fmt.Errorf("call error: GET [%s]", e.Error())
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bad status code [%d]", r.StatusCode)
	}

	downloadedBytes += r.ContentLength
	readBytes += r.ContentLength

	text, e := ioutil.ReadAll(r.Body)
	if e != nil {
		return "", fmt.Errorf("cannot read response [%s]", e.Error())
	}

	if e := as.add(url, text); e != nil {
		log("Cannot cache entry [%s] -- [%s]\n", url, e.Error())
	}

	return string(text), nil
}

// downloads and constructs the assets list
func constructAssetList(hc *http.Client, as *assetCache, listUrl string, isCustomUrl bool, foriOS bool) (assetList []*assetListItem, err error) {
	if foriOS && isCustomUrl {
		assetList = []*assetListItem{{
			name:       listUrl,
			content:    "custom",
			group:      "custom",
			contentURL: listUrl,
		}}

		return
	}

	assetList = make([]*assetListItem, 0)
	assets := make(map[string]assetItem)
	var data string
	if data, err = fetchText(hc, as, listUrl); err != nil {
		return
	}

	if err = json.Unmarshal([]byte(data), &assets); err != nil {
		return nil, fmt.Errorf("cannot unmarshal json [%s]", err.Error())
	}

	for name, a := range assets {
		//log("\t[%s]-[%s][%s][%s][%s]\n", name, a.Title, a.Content, a.Group, a.ContentURL)
		log("  [%30s][%30s]\n", a.Content, a.Group)
		/// read everything except internal assets, and region specific assets
		if a.Content != "filters" || a.Group == "regions" {
			continue
		}

		if ustrslice, ok := a.ContentURL.([]interface{}); ok {
			for _, u := range ustrslice {
				/// use only https links
				if ustr, ok := u.(string); ok && strings.HasPrefix(ustr, "https://") {
					al := &assetListItem{
						name:       name,
						content:    a.Content,
						group:      a.Group,
						contentURL: ustr,
					}
					assetList = append(assetList, al)
				}
			}
		}
	}

	if !foriOS {
		//assetList = append(assetList, &assetListItem{
		//	name:       "filter",
		//	content:    "filter",
		//	group:      "filter",
		//	contentURL: "https://update.avastbrowser.com/adblock/filterlist.txt",
		//})

		//assetList = append(assetList, &assetListItem{
		//	name:       "aas",
		//	content:    "aas",
		//	group:      "aas",
		//	contentURL: "https://easylist-downloads.adblockplus.org/exceptionrules.txt",
		//})

		//if customListURL != "" {
		//	assetList = append(assetList, &assetListItem{
		//		name:       "asbexception",
		//		content:    "asbexception",
		//		group:      "asbexception",
		//		contentURL: customListURL,
		//	})
		//}
	}

	return
}
