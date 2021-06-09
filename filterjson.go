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
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

type filterTrigger struct {
	URLFilter    string   `json:"url-filter"`
	IfDomain     []string `json:"if-domain,omitempty"`
	UnlessDomain []string `json:"unless-domain,omitempty"`
	ResourceType []string `json:"resource-type,omitempty"`
	LoadType     []string `json:"load-type,omitempty"`
	IfTopURL     []string `json:"if-top-url,omitempty"`
	UnlessTopURL []string `json:"unless-top-url,omitempty"`
}

type filterAction struct {
	Type     string `json:"type"`
	Selector string `json:"selector,omitempty"`
}

type filterElement struct {
	Trigger  *filterTrigger `json:"trigger"`
	Action   *filterAction  `json:"action"`
	Original string         `json:"-"`
	File     string         `json:"-"`
}

func constructFilterJSON(hc *http.Client,
	as *assetCache,
	assetFilename string,
	assetList []*assetListItem,
	iOSFilterCutoffNo int,
) (e error) {
	assetText := ""
	var g *rawGraphElement
	ret := make([]*filterElement, 0)
	dedup := make(map[string]bool)
	exceptionNum := 0

	for _, a := range assetList {
		log("Loading ASSET [%s][%s]\n", a.name, a.contentURL)

		if assetText, e = fetchText(hc, as, a.contentURL); e != nil {
			log("Cannot load asset [%s] - [%s]\n", a.name, e.Error())
			continue
		}

		lines := splitIntoLines(assetText)
		//log("[%s][%s][%s]\n\t[%s]\n", a.name, a.content, a.contentURL, lines[0])
		for i, l := range lines {
			if _, ok := dedup[l]; ok {
				continue
			}
			dedup[l] = true

			if strings.Contains(l, "badfilter") || strings.Contains(l, "https?") || strings.Contains(l, "127.0.0.1") {
				continue
			}

			if len(l) == 0 {
				continue
			}

			if g, e = parseLine(l, true); e != nil && g != nil && !strings.HasPrefix(e.Error(), "cannot handle options") {
				log("Parse error :: [%s:%s][%d] `%s`\n", a.name, a.contentURL, i+1, e.Error())
				continue
			}

			if g != nil && g.token != "" {
				toAdd := &filterElement{Original: l, File: a.name}

				if strings.Contains(g.token, ",") {
					continue
				}

				if strings.Contains(l, "youtube.com/api/stats") {
					fmt.Printf("YTADS:: [%s]\n", g.token)
				}

				/// expand the separator in-place
				g.token = strings.Replace(g.token, ".", `\.`, -1)
				g.token = strings.Replace(g.token, "?", `\?`, -1)
				g.token = strings.Replace(g.token, "+", `\+`, -1)
				g.token = strings.Replace(g.token, "[", `\[`, -1)
				g.token = strings.Replace(g.token, "]", `\]`, -1)

				if strings.Contains(l, "youtube.com/api/stats") {
					fmt.Printf("YTADS2:: [%s]\n", g.token)
				}

				if g.flags&flagSeparator != 0 {
					g.token = strings.Replace(g.token, "^", separatorCharClass, -1)
				}
				if g.flags&flagWildCard != 0 {
					g.token = strings.Replace(g.token, "*", ".*", -1)
				}
				if g.flags&flagPipeStart != 0 {
					g.token = strings.Replace(g.token, "|", ".*", -1)
				}

				if strings.Contains(l, "youtube.com/api/stats") {
					fmt.Printf("YTADS3:: [%s]\n", g.token)
				}

				if g.flags&flagPipeStart == 0 && g.flags&flagDoublePipe == 0 {
					g.token = ".*" + g.token
				} else if g.flags&flagDoublePipe != 0 {
					g.token = `^(?:https?://)?(?:www\.)?` + g.token
				}

				if g.flags&flagPipeEnd == 0 {
					g.token += ".*"
				}

				if strings.Contains(l, "youtube.com/api/stats") {
					fmt.Printf("YTADS4:: [%s]\n", g.token)
				}

				toAdd.Trigger = &filterTrigger{
					URLFilter:    g.token,
					IfDomain:     nil,
					UnlessDomain: nil,
					ResourceType: nil,
					LoadType:     nil,
					IfTopURL:     nil,
					UnlessTopURL: nil,
				}

				toAdd.Action = &filterAction{
					Type: "block",
				}

				if g.flags&flagException != 0 {
					exceptionNum++
					toAdd.Action.Type = "ignore-previous-rules"
				} else if g.domexception != "" {
					exceptionNum++
					toAdd.Action.Type = "ignore-previous-rules"
					toAdd.Action.Selector = g.domexception
				} else if g.domfilter != "" {
					toAdd.Action.Type = "css-display-none"
					toAdd.Action.Selector = g.domfilter
				}

				if g.opts != nil {
					if len(g.opts.opts) == 0 { // if we should have options (we have them declared in filter list), but we don't support it
						// it's safer to just ignore the rule altogether
						continue
					}

					if g.opts.opts["script"] {
						toAdd.Trigger.ResourceType = append(toAdd.Trigger.ResourceType, "script")
					}
					if g.opts.opts["image"] {
						toAdd.Trigger.ResourceType = append(toAdd.Trigger.ResourceType, "image")
					}
					if g.opts.opts["stylesheet"] {
						toAdd.Trigger.ResourceType = append(toAdd.Trigger.ResourceType, "style-sheet")
					}
					if g.opts.opts["object"] {
						toAdd.Trigger.ResourceType = append(toAdd.Trigger.ResourceType, "raw", "media") // ???
					}
					if g.opts.opts["subdocument"] || g.opts.opts["document"] || g.opts.opts["frame"] {
						//fmt.Printf("Ignoring document!!!\n")
						toAdd.Trigger.ResourceType = append(toAdd.Trigger.ResourceType, "document")
					}
					if g.opts.opts["xmlhttprequest"] || g.opts.opts["websocket"] || g.opts.opts["webrtc"] || g.opts.opts["xhr"] {
						toAdd.Trigger.ResourceType = append(toAdd.Trigger.ResourceType, "raw")
					}
					if g.opts.opts["popup"] || g.opts.opts["popunder"] {
						toAdd.Trigger.ResourceType = append(toAdd.Trigger.ResourceType, "popup")
					}
					if g.opts.opts["domain"] {
						//fmt.Printf("domain token is [%v]/[%v] -- [%s]\n\n\n", g.opts.ifdomains, g.opts.unlessdomains, l)

						if g.opts.ifdomains != nil {
							toAdd.Trigger.IfDomain = g.opts.ifdomains
						} else if g.opts.unlessdomains != nil {
							toAdd.Trigger.UnlessDomain = g.opts.unlessdomains
							toAdd.Action.Type = "ignore-previous-rules"
						}

						// handle spawning of 2 toAdd objects, one for blocking, and one for exemption

					}
					if g.opts.opts["all"] {
						//continue
						toAdd.Trigger.ResourceType = nil
					}

					tp := g.opts.opts["3p"] || g.opts.opts["third-party"]
					fp := g.opts.opts["1p"]

					if tp == fp { /// block all load types OR have no preference about load type, either way this field remains empty
						// NOP
					} else if tp {
						toAdd.Trigger.LoadType = append(toAdd.Trigger.LoadType, "third-party")
					} else if fp {
						toAdd.Trigger.LoadType = append(toAdd.Trigger.LoadType, "first-party")
					}

				} else {
					// all except main document
					//toAdd.Trigger.ResourceType = []string{"script", "image", "style-sheet", "raw", "media", "popup", "svg-document"}
					//continue
				}

				if g.token == ".*" || g.token == ".*.*" || g.token == ".*.*.*" || g.token == ".*.*.*.*" {
					continue
				} else {
					//if strings.Contains(l, "||youtube.com/pagead/") {
					//	log("YT ADS:: [%d][%v][%s]\n[%v]\n[%v]\n", g.flags, g.opts, l, toAdd.Trigger, toAdd.Action)
					//	os.Exit(0)
					//}
					if strings.Contains(l, "youtube.com/api/stats") {
						fmt.Printf("YTADS5:: [%s]\n", g.token)
					}

					ret = append(ret, toAdd)
				}
			}
		}
	}

	log("Overall downloaded [%d]KB of data.\n", downloadedBytes/1024)
	log("Filter set is [%d]KB.\n", readBytes/1024)
	log("JSON ruleset has [%d] rules\n", len(ret))
	log("Of which [%d] is exception\n", exceptionNum)
	log("Pushing JSON filter.\n")

	//fmt.Printf("Commencing TEST")
	//
	//type regel struct {
	//	re *regexp.Regexp
	//	filter *iosFilterElement
	//	line string
	//	file string
	//}
	//
	//regs := []regel{}
	//for _, el := range ret {
	//	regs = append(regs, regel{
	//		re:   regexp.MustCompile(el.Trigger.URLFilter),
	//		filter: el,
	//		line: el.Original,
	//		file: el.File,
	//	})
	//}
	//fmt.Printf("Regexes built. yay\n")
	//
	//reader := bufio.NewReader(os.Stdin)
	//fmt.Printf("Enter query\n")
	//for {
	//	input, _ := reader.ReadString('\n')
	//	input = input[:len(input)-1]
	//	if input == "q" {
	//		break
	//	}
	//	fmt.Printf("You have entered [%s]. Checking for matches.\n", input)
	//
	//	for _, reg := range regs {
	//
	//		if reg.re.MatchString(input) {
	//			fmt.Printf("MATCH:: [%s][%s]\n\t[%v]\n\t[%v]\n\n", reg.line, reg.file, reg.filter.Trigger, reg.filter.Action)
	//		}
	//
	//
	//	}
	//
	//}

	partitionedRet := [][]*filterElement{}
	for {
		if len(ret) > iOSFilterCutoffNo {
			partitionedRet = append(partitionedRet, ret[:iOSFilterCutoffNo])
			ret = ret[iOSFilterCutoffNo:]
		} else {
			partitionedRet = append(partitionedRet, ret)
			break
		}
	}

	for i, fs := range partitionedRet {
		outBytes := &bytes.Buffer{}
		encoder := json.NewEncoder(outBytes)
		encoder.SetEscapeHTML(false)

		//encoder.SetIndent("", "    ")
		if err := encoder.Encode(fs); err != nil {
			return err
		} else {
			ioutil.WriteFile(assetFilename+fmt.Sprintf(".%003d", i+1), outBytes.Bytes(), 0644)
		}
	}

	//for _, elem := range uniqueRet {
	//	if elem.suffix == "" {
	//		continue
	//	}
	//	/// escape meta chars
	//	elem.suffix = regexp.QuoteMeta(elem.suffix)
	//	elem.suffix = strings.Replace(elem.suffix, "/", "\\/", -1)
	//	/// if there's a wildcard, expand it into it's regex form (* -> .*)
	//	if ind := strings.Index(elem.suffix, "*"); ind != -1 {
	//		elem.suffix = strings.Replace(elem.suffix, "\\*", ".*", -1)
	//	}
	//
	//	/// expand the separator into it's regex form (^ -> [\/:?=&])
	//	if elem.flags&flagSeparator > 0 {
	//		elem.suffix = strings.Replace(elem.suffix, "\\^", `[\/:?=&]`, -1)
	//	}
	//}

	return nil
}
