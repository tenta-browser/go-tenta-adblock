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
	"strings"
	"unicode"
)

var optsValidator = map[string]bool{
	"1p":             true,
	"3p":             true,
	"all":            true,
	"document":       true,
	"domain":         true,
	"frame":          true,
	"image":          true,
	"object":         true,
	"popunder":       true,
	"popup":          true,
	"script":         true,
	"stylesheet":     true,
	"subdocument":    true,
	"third-party":    true,
	"webrtc":         true,
	"websocket":      true,
	"xhr":            true,
	"xmlhttprequest": true,
}

type filterOptions struct {
	//script, image, stylesheet, object, subdocument, xhr, ws, webrtc, popup, generichide, genericblock, document, elemhide, domain, thirdparty bool
	opts          map[string]bool
	ifdomains     []string
	unlessdomains []string
}

func isASCII(s string) bool {
	for _, c := range s {
		if c > unicode.MaxASCII {
			return false
		}
	}

	return true
}

func newFilterOptions(opts string) (*filterOptions, error) {
	ret := &filterOptions{
		opts:          make(map[string]bool),
		ifdomains:     []string{},
		unlessdomains: []string{},
	}

	toks := strings.Split(opts, ",")
	if len(toks) == 0 {
		return nil, fmt.Errorf("no options")
	}

	var negation bool
	for _, tok := range toks {
		negation = false
		tok = strings.TrimSpace(tok)
		if tok[0] == '~' {
			negation = true
			tok = tok[1:]
		}

		/// special check for domain=... token
		if strings.HasPrefix(tok, "domain=") {
			tok = tok[7:]
			doms := strings.Split(tok, "|")
			if len(doms) == 0 {
				log("Error parsing domain literals from [%s]\n", tok)
				continue
			}

			for _, dom := range doms {
				if dom[0] == '~' {
					if isASCII(dom[1:]) {
						ret.unlessdomains = append(ret.unlessdomains, strings.ToLower(dom[1:]))
					} else {
						log("Skipping non-ascii domain: [%s]\n", dom[1:])
					}
				} else {
					if isASCII(dom) {
						ret.ifdomains = append(ret.ifdomains, strings.ToLower(dom))
					} else {
						log("Skipping non-ascii domain: [%s]\n", dom)
					}
				}
			}
			//fmt.Printf(">>>>>>Parsed domains! [%v]/[%v]\n", ret.ifdomains, ret.unlessdomains)
			tok = "domain"
		}

		if _, ok := optsValidator[tok]; !ok {
			//log("Ignoring non-supported option token [%s]\n", tok)
			return nil, fmt.Errorf("not supported token: [%s]", tok)
		}

		ret.opts[tok] = !negation
	}

	return ret, nil
}
