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
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	graph "github.com/tenta-browser/go-graph"
)

var (
	pProtocolSubdomain = regexp.MustCompile(reProtocolSubdomain)
)

type sortableGraphInput []*rawGraphElement

/// implement sort functions for graph input
func (s sortableGraphInput) Len() int {
	return len(s)
}

func (s sortableGraphInput) Less(i, j int) bool {
	return s[i].token < s[j].token
}

func (s sortableGraphInput) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// constructFilter -- constructs a directed acyclic word graph - based filter
func constructFilter(
	hc *http.Client,
	as *assetCache,
	assetFilename string,
	assetList []*assetListItem,
	debug bool,
) (ret sortableGraphInput, e error) {
	assetText := ""
	var assetTextB []byte
	var g *rawGraphElement
	ret = make(sortableGraphInput, 0)

	for _, a := range assetList {
		log("Loading ASSET [%s][%s]\n", a.name, a.contentURL)

		if a.name != "asbexception" {
			if assetText, e = fetchText(hc, as, a.contentURL); e != nil {
				log("Cannot load asset [%s] - [%s]\n", a.name, e.Error())
				continue
			}
		} else {
			if assetTextB, e = ioutil.ReadFile(a.contentURL); e != nil {
				log("Cannot load asset [%s] - [%s]\n", a.name, e.Error())
				continue
			}
			assetText = string(assetTextB)
		}

		lines := splitIntoLines(assetText)
		//log("[%s][%s][%s]\n\t[%s]\n", a.name, a.content, a.contentURL, lines[0])
		for i, l := range lines {
			//log("LINE::[%s]\n", l)
			if len(l) == 0 {
				continue
			}

			if g, e = parseLine(l, false); e != nil && g != nil && !strings.HasPrefix(e.Error(), "cannot handle options") {
				log("Parse error :: [%s:%s][%d] `%s`\n", a.name, a.contentURL, i+1, e.Error())
				continue
			}

			if g != nil && g.token != "" {
				if strings.Contains(g.token, "buysellads") {
					log("[CHECK]:: [%s] [%s] [%s]\n", g.token, g.original, formatFlags(g.flags))
				}

				if g.flags&flagWildCard > 0 {
					temp := strings.Split(g.token, "*")
					if len(temp) >= 2 {
						g.token = temp[0]
						g.suffix = strings.Join(temp[1:], "*")
					}
				}

				g.filter = a.name
				/// make sure the separator is still instide the token (not detached in the suffix)
				if g.flags&flagSeparator > 0 && strings.Contains(g.token, "^") {
					for _, sym := range separatorExpansion {
						tempTok := strings.Replace(g.token, "^", string(sym), -1)
						ret = append(ret, &rawGraphElement{tempTok, g.suffix, g.flags, g.original, g.filter, nil, "", ""})
					}
				} else { /// if no separator is present, just add the token like usual
					ret = append(ret, g)
				}
			}
		}
	}

	hackyDeduplicator := map[string]*rawGraphElement{}

	for _, e := range ret {
		hackyDeduplicator[e.token] = e
	}

	uniqueRet := sortableGraphInput{}
	charCount, wcCount := 0, 0
	for _, v := range hackyDeduplicator {
		uniqueRet = append(uniqueRet, v)
		charCount += len(v.token)
		wcCount += len(v.suffix)
	}

	log("Overall downloaded [%d]KB of data.\n", downloadedBytes/1024)
	log("Filter set is [%d]KB.\n", readBytes/1024)
	log("Sorting tokens for graph input.\n")
	sort.Sort(uniqueRet)

	for _, elem := range uniqueRet {
		if elem.suffix == "" {
			continue
		}
		/// escape meta chars
		elem.suffix = regexp.QuoteMeta(elem.suffix)
		elem.suffix = strings.Replace(elem.suffix, "/", "\\/", -1)
		/// if there's a wildcard, expand it into it's regex form (* -> .*)
		if ind := strings.Index(elem.suffix, "*"); ind != -1 {
			elem.suffix = strings.Replace(elem.suffix, "\\*", ".*", -1)
		}

		/// expand the separator into it's regex form (^ -> [\/:?=&])
		if elem.flags&flagSeparator > 0 {
			elem.suffix = strings.Replace(elem.suffix, "\\^", `[\/:?=&]`, -1)
		}
	}

	log("Okay. Trying to construct word graph. Stand by.\n")
	d := graph.NewDawg()
	for _, input := range uniqueRet {
		if debug {
			d.Insert(input.token, &ubDebugPayload{
				ubPayload: &ubPayload{
					flags:  input.flags,
					suffix: input.suffix,
				},
				list:     input.filter,
				original: input.original,
			})
		} else if input.flags != 0 {
			d.Insert(input.token, &ubPayload{
				flags:  input.flags,
				suffix: input.suffix,
			})
		} else {
			d.Insert(input.token, nil)
		}
	}
	d.Finish()

	log("Constructed. [%d] and [%d] are the stats, out of [%d]/[%d] characters\n", d.EdgeCount(), d.NodeCount(), charCount, wcCount)
	log("Flushing graph asset to %s\n\n", assetFilename)

	c := d.Serialize(assetFilename)

	// test filter
	test, err := Deserialize(c)
	if err != nil {
		return nil, fmt.Errorf("unable to create filter for test: %s", err)
	}

	tests := []string{
		"&ctxId=",
		"&ctxId=asd&pubId=qwe&objId=zxc",
		"shoudntmmatch",
		".com/js/ga-123qweasd^.js",
		"www.doubleclick.net",
		"sjs.bizographics.com",
		"http://buysellads.com/ac/bsa.js",
		"https://pixiedust.buzzfeed.com/events",
		"https://www.gstatic.com/kpui/social/fb_32x32.png",
		"https://www.yahoo.com/lib/metro/g/myy/advertisement_0.0.19.js",
		"https://s.yimg.com/dy/ads/native.js",
		"http://buysellads.com/ac/bsa.js",
		"https://jill.fc.yahoo.com/v1/client/js?tagType=async",
		"https://sp.analytics.yahoo.com/sp.pl?a=10000&d=Fri%2C%2005%20Mar%202021%2005%3A14%3A48%20GMT&n=-2&ea=page_view",
	}

	for _, t := range tests {
		st := time.Now()
		ret, _ := test.Search(t)
		//ret, _ := plainSearch(d, t)
		log("Test is [%v] -- [%v] [%s]\n\n", time.Since(st), ret, t) //, graph.MatchStatusToString[res.MatchStatus], res.Remainder, res.Payload)
	}

	return uniqueRet, nil
}

/// search, using debug payloads (TODO: add interface type checking to UBlockHelper functions, and ubDebugPayload encode/decode implementation)
func plainSearch(d *graph.Dawg, URL string) (bool, error) {
	if d == nil {
		return false, errors.New("graph is not initialized")
	}

	proposedRet := false

	for i := range URL {
		log("doing exact lookup for [%s]", URL[i:])
		result := d.ExactLookupWithPayload(URL[i:])
		if result.MatchStatus == graph.MatchNotFound {
			continue
		}
		/// verify the result
		/// no payload -> no constraint over match, return true
		if result.Payload == nil {
			log("returning true for [%s]\n", URL[i:])
			//return true, nil
			proposedRet = true
			continue
		}
		/// evaluate the payload
		log("We have a loaded match with [%s][%s]\n", result.Remainder, result.Payload.(*ubDebugPayload).String())
		if !result.Payload.(*ubDebugPayload).Evaluate(result.Remainder) {
			log("remainder does not evaluate\n")
			continue
		}

		flg := result.Payload.(*ubDebugPayload).flags
		/// exception -> permitting access
		if flg&flagException > 0 {
			log("returning false, reason exception\n")
			return false, nil
		}
		/// check flag constraints vs match
		/// absolute start/end of URL
		if (flg&flagPipeStart > 0 && i != 0) || (flg&flagPipeEnd > 0 && result.Remainder != "") {
			continue
		}
		/// domain name start
		if flg&flagDoublePipe > 0 {
			// log("Matching regex [%s] to [%s] => [%v] [%v]\n", pProtocolSubdomain.String(), URL[:i], pProtocolSubdomain.MatchString(URL[:i]), pProtocolSubdomain.FindStringSubmatch(URL[:i]))
			if dom := pProtocolSubdomain.FindStringSubmatch(URL[:i]); len(dom) > 0 && strings.Compare(dom[0], URL[:i]) == 0 {
				continue
			}
		}
		/// no constrain stuck, no choice but to return true
		log("Search true -- from [%s]\n", result.Payload.(*ubDebugPayload).original)
		proposedRet = true
		//return true, nil
	}
	return proposedRet, nil
}
