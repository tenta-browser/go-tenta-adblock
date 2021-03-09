/**
 * Go uBlock
 *
 *    Copyright 2018 Tenta, LLC
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
 *
 * ublock.go: Go uBlock implementation
 */
package ublock

import (
	//"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"unicode"

	//"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	graph "github.com/tenta-browser/go-graph"

)

const (
	uBlockAssets       = "https://raw.githubusercontent.com/gorhill/uBlock/master/assets/assets.json"
	separatorExpansion = `:/?=&`
	separatorCharClass = "[" + separatorExpansion + "]+"
	compileDebugAsset  = false
	cacheValidity      = 24 * time.Hour
	iOSFilterCutoffNo  = 40000 // it's probably 30k, but safety first -- the number of rules that can fit into one JSON
)

type assetItem struct {
	Content, Title, SupportURL, Group string
	ContentURL                        interface{}
	UpdateAfter                       float64
	Off                               bool
}

type assetListItem struct {
	name, content, group, contentURL string
}

type iosFilterElement struct {
	Trigger *iosFilterTrigger `json:"trigger"`
	Action *iosFilterAction `json:"action"`
	Original string `json:"-"`
	File string `json:"-"`
}

type iosFilterTrigger struct {
	URLFilter string `json:"url-filter"`
	IfDomain []string `json:"if-domain,omitempty"`
	UnlessDomain []string `json:"unless-domain,omitempty"`
	ResourceType []string `json:"resource-type,omitempty"`
	LoadType []string `json:"load-type,omitempty"`
	IfTopURL []string `json:"if-top-url,omitempty"`
	UnlessTopURL []string `json:"unless-top-url,omitempty"`
}

type iosFilterAction struct {
	Type string `json:"type"`
	Selector string `json:"selector,omitempty"`
}

type rawGraphElement struct {
	token    string
	suffix   string
	flags    int
	original string
	filter   string
	opts *filterOptions
	domfilter, domexception string
}

var optsValidator = map[string]bool {"script": true, "image": true, "stylesheet": true, "object": true, "subdocument": true, "xmlhttprequest": true,
	"websocket": true, "webrtc": true, "popup": true, "popunder": true, "domain": true, "3p": true, "1p": true, "all": true, "document": true,
	"frame": true, "xhr": true, "third-party": true}


type filterOptions struct {
	//script, image, stylesheet, object, subdocument, xhr, ws, webrtc, popup, generichide, genericblock, document, elemhide, domain, thirdparty bool
	opts map[string]bool
	ifdomains []string
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
		opts: make(map[string]bool),
		ifdomains:     []string{},
		unlessdomains: []string{},
	}

	toks := strings.Split(opts, ",")
	if toks == nil || len(toks) == 0 {
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
			if doms == nil || len(doms) == 0 {
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
						log("Skipping non-ascii domain: [%s]\n",  dom)
					}
				}
			}
			//fmt.Printf(">>>>>>Parsed domains! [%v]/[%v]\n", ret.ifdomains, ret.unlessdomains)
			tok = "domain"

		}

		if _, ok := optsValidator[tok]; !ok {
			//log("Ignoring non-supported option token [%s]\n", tok)
			return nil, fmt.Errorf("Not supported token: [%s]", tok)
		}

		ret.opts[tok] = !negation
	}

	return ret, nil
}

type sortableGraphInput []*rawGraphElement

/// ublock specific payload definition and interface implementation
type ubPayload struct {
	flags  int
	suffix string
}

/// ublock specific debugging payload (contains filter info)
type ubDebugPayload struct {
	*ubPayload
	list, original string
}

/// package-wide logging flag
var loggingEnabled = true

// SetLoggingEnabled -- toggle logging for package
func SetLoggingEnabled(b bool) {
	loggingEnabled = b
}

func log(format string, args ...interface{}) {
	if loggingEnabled == true {
		fmt.Printf(format, args...)
	}
}

// Encode -- encodes the ublock specific payload. returns a string([]byte),
// in which the flags are added as plaintext characters (number + ord('a')).
// This keeps byte num lower (2^6 - 1 = 63 ~> 2bytes + 1byte for declaring the length of the length-encode)
// and the overall sequence has much better compressability
func (p *ubPayload) Encode() []byte {
	retString := strconv.Itoa(p.flags)
	fl := strconv.Itoa(len(retString))
	retString = fl + retString + p.suffix
	return []byte(retString)
}

// Decode -- follows the logic (inversely) laid out in Encode()
func (p *ubPayload) Decode(enc []byte) (graph.NodePayload, error) {
	in := string(enc)
	l := in[0] - charOffset
	flags, e := strconv.Atoi(in[1 : 1+l])
	if e != nil {
		return nil, e
	}
	ret := &ubPayload{flags: flags, suffix: in[1+l:]}
	return ret, nil
}

// String -- string representation of the payload
func (p *ubPayload) String() string {
	return fmt.Sprintf("[%s][%s]", formatFlags(p.flags), p.suffix)
}

// String -- string representation of payload with debug information
func (p *ubDebugPayload) String() string {
	return fmt.Sprintf("[%s][%s][%s][%s]", formatFlags(p.flags), p.suffix, p.original, p.list)
}

// Evaluate -- evaluates the remainder from an uncertain match. True means a match is made, false means no match
func (p *ubPayload) Evaluate(remainder string) bool {
	re, e := regexp.Compile(p.suffix)
	if e != nil {
		return false
	}
	return re.MatchString(remainder)
}

var assetList = make([]*assetListItem, 0)
var downloadedBytes, readBytes int64
var cachedAssets = make(map[string]string, 0)
var charOffset = "0"[0]

/* regex capture groups
 0 - full match
 1 - comment
 2 - exception
 3 - host entry
 4 - regex entry
 5 - domain entry
 6 - pipe start
 7 - url part entry
 8 - pipe end
 9 - filter options
10 - dom/css filter options
*/

/// regex classes
const (
	/// regex defining legal chars in url part describing classes, or eats up justdomain type of lists too
	///                                                [\|]* -- removed
	reURLPart = `(?:[\w\.\-\:\/\+\&\=\?\*\;\,\~\%\^\@]+[\w\.\-\:\/\+\&\=\?\*\;\,\~\!\]\[\^\@]*)*`
	/// three types of comments occuring in adblock plus filter definitions
	reCommentGroup = `((?:\[[\w .]+\])|(?:\#.*)|(?:\!.*))`
	/// exact address type filter
	reFreeFormEntry = `(?:(` + reURLPart + `))`
	/// fixed start and/or end type filter
	reStartEndDefined = `(?:(\|)?(` + reURLPart + `)(\|)?)`
	/// domain filter
	reDomain = `(?:\|\|(` + reURLPart + `))`
	/// host format
	reHost = `[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[\s]+([\w\.\-]+)`
	/// regular expression filters (this one is ugly, it basically hangs on the idea of the regex having at least one char class)
	reRegex = `\/((?:[\w\.\-\:\+\&\=\?\*\|\;\,\{\}\$\^\\\/\(\)]*[\[\]]*[\w\.\-\:\+\&\=\?\*\|\;\,\{\}\$\\\/\(\)]*)+)\/`
	/// filtering parameters -- aggregated form, v0.1 can't handle these
	reFilterParams = `(?:\$(.+))?`
	/// exception token catcher
	reException     = `(\@\@)?`
	reDOMFilter     = `(\#\#.*|\#\?\#.*|\#\@\#.*)?` /// android/other will receive this as tokens[10] which it will ignore
	reDOMFilterIOS  = `(?:\#\#(.*))?(?:\#\@\#(.*))?(|\#\?\#.*|\#\$\#.*)?` /// for iOS (JSON content filtering) we capture CSS selectors and CSS selector exceptions
	reArgumentGroup = `(?:` + reHost + `|` + reRegex + `|` + reDomain + `|` + reStartEndDefined + `)`
	reEntry         = `^` + reCommentGroup + `|` + reException + reArgumentGroup + reFilterParams + reDOMFilter + `$`
	reEntryIOS = `^` + reCommentGroup + `|` + reException + reArgumentGroup + reFilterParams + reDOMFilterIOS + `$`
	/// regex for protocol+subdomain parsing from URL (used in double pipe case)
	reProtocolSubdomain = `^(?:[\w-+.]+://)?(?:(?:` + reURLPart + `)\.)*$`
)

/// graph unit flags
const (
	flagException  = 1 << iota
	flagPipeStart  = 1 << iota
	flagPipeEnd    = 1 << iota
	flagDoublePipe = 1 << iota
	flagSeparator  = 1 << iota
	flagWildCard   = 1 << iota
	flagNum        = 6
)

var flagToString = map[int]string{flagException: "Exception", flagPipeStart: "Start anchor", flagPipeEnd: "End anchor",
	flagDoublePipe: "Domain name anchor", flagSeparator: "Separator", flagWildCard: "Wildcard"}

var (
	pEntry             = regexp.MustCompile(reEntry)
	pEntryIOS = regexp.MustCompile(reEntryIOS)
	pProtocolSubdomain = regexp.MustCompile(reProtocolSubdomain)
)

var (
	vaultDir      string
	assetFilename string
	customListURL string
	useCustomURL bool
)

// UBlockHelper -- object to use in superior layers.
type UBlockHelper struct {
	m sync.Mutex
	d *graph.Dawg
}

/// UBlockHelper convenience exports

// Deserialize -- Deserializes the graph
func (u *UBlockHelper) Deserialize(enc []byte) *UBlockHelper {
	localCopy := make([]byte, len(enc))
	copy(localCopy, enc)
	go func() {
		u.m.Lock()
		defer u.m.Unlock()
		u.d = graph.Deserialize(localCopy, nil, &ubPayload{})
		if u.d == nil {
			/// log the error
		}
	}()

	return u
}

// Search -- returns true if networking should block request, false otherwise
func (u *UBlockHelper) Search(URL string) (bool, error) {
	proposedRet := false
	u.m.Lock()
	defer u.m.Unlock()
	if u.d == nil {
		return false, fmt.Errorf("graph is not initialized")
	}
	for i := range URL {
		result := u.d.ExactLookupWithPayload(URL[i:])
		if result.MatchStatus == graph.MatchNotFound {
			continue
		}
		/// verify the result
		/// no payload -> no constraint over match, return true
		if result.Payload == nil {
			//return true, nil
			proposedRet = true
			continue
		}
		/// evaluate the payload
		log("We have a loaded match with [%s][%s]\n", result.Remainder, result.Payload.(*ubPayload).String())
		if !result.Payload.(*ubPayload).Evaluate(result.Remainder) {
			//log("Reminder not evaluated.\n")
			continue
		}

		flg := result.Payload.(*ubPayload).flags
		/// exception -> permitting access
		if flg&flagException > 0 {
			//log("Exception -> false")
			return false, nil
		}
		/// check flag constraints vs match
		/// absolute start/end of URL
		if (flg&flagPipeStart > 0 && i != 0) || (flg&flagPipeEnd > 0 && result.Remainder != "") {
			//log("cannot match pipes vs remainder\n")
			continue
		}
		/// domain name start
		if flg&flagDoublePipe > 0 {
			if pProtocolSubdomain.MatchString(URL[:i]) == false {
				continue
			}
		}
		/// no constrain stuck, no choice but to return true
		//log("")
		proposedRet = true
		continue
	}
	return proposedRet, nil
}

/// search, using debug payloads (TODO: add interface type checking to UBlockHelper functions, and ubDebugPayload encode/decode implementation)
func plainSearch(d *graph.Dawg, URL string) (bool, error) {
	proposedRet := false
	if d == nil {
		return false, fmt.Errorf("Graph is not initialized.")
	}
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
			if dom := pProtocolSubdomain.FindStringSubmatch(URL[:i]); dom != nil && len(dom) > 0 && strings.Compare(dom[0], URL[:i]) == 0 {
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

/// implement sort functions for graph input
func (s sortableGraphInput) Len() int {
	return len(s)
}

func (s sortableGraphInput) Less(i, j int) bool {
	if s[i].token < s[j].token {
		return true
	}
	return false
}

func (s sortableGraphInput) Swap(i, j int) {
	temp := s[i]
	s[i] = s[j]
	s[j] = temp
}

func formatFlags(flags int) (s string) {
	s += "FLAGS:"
	for i := uint(0); i < flagNum; i++ {
		if flgStr, ok := flagToString[flags&(1<<i)]; ok {
			s += " " + flgStr
		}
	}
	return
}

// Init - initialize for the export side of operations, do not use in client application (for filtering)
func Init(filterCacheDir, assetName, customUrl string) error {
	if filterCacheDir == "" || assetName == "" {
		return fmt.Errorf("unable to work with empty files or directories")
	}

	vaultDir = filterCacheDir
	assetFilename = assetName
	if customUrl != "" {
		customListURL = customUrl
		useCustomURL = true
	}
	log("Using regex [%s]\n\n", pEntry.String())


	log("Using regex [%s]\n\n", pEntryIOS.String())
	fil, e := ioutil.ReadDir(vaultDir)
	if e != nil {
		log("readdir err [%s]", e.Error())
		return e
	}
	/// read cached files
	for _, fi := range fil {
		if fi.IsDir() == true {
			continue
		}
		if time.Now().Sub(fi.ModTime()) > cacheValidity {
			//os.Remove(vaultDir + fi.Name())
			continue
		}
		fileContent, e := ioutil.ReadFile(vaultDir + fi.Name())
		if e != nil {
			log("Error reading file [%s] -- [%s]\n", fi.Name(), e.Error())
			continue
		}
		cachedAssets[fi.Name()] = string(fileContent)
	}
	return nil
}

/// fetches (cache/network) a filter file
func fetchText(url string) (string, error) {
	fnameURL := strings.Replace(url, "/", "_", -1)
	fnameURL = strings.Replace(fnameURL, ":", "_", -1)
	if content, ok := cachedAssets[fnameURL]; ok {
		// log("Returning from cache for [%s].\n", url)
		readBytes += int64(len(content))
		return content, nil
	}
	// log("Downloading asset for [%s].\n", url)
	r, e := http.Get(url)
	if e != nil {
		return "", fmt.Errorf("cannot GET [%s]", e.Error())
	}
	downloadedBytes += r.ContentLength
	readBytes += r.ContentLength
	defer r.Body.Close()
	text, e := ioutil.ReadAll(r.Body)
	if e != nil {
		return "", fmt.Errorf("cannot read response [%s]", e.Error())
	}
	if e := ioutil.WriteFile(vaultDir+fnameURL, text, 0755); e != nil {
		log("Cannot cache entry [%s] -- [%s]\n", url, e.Error())
	}
	return string(text), nil
}

func constructAssetList(foriOS bool) error {

	if !foriOS || !useCustomURL {
		assets := make(map[string]assetItem)
		assetsJSON, e := fetchText(uBlockAssets)
		if e != nil {
			return e
		}
		if e := json.Unmarshal([]byte(assetsJSON), &assets); e != nil {
			return fmt.Errorf("cannot unmarshal json [%s]", e.Error())
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
						al := &assetListItem{name: name, content: a.Content, group: a.Group, contentURL: ustr}
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
	} else {
		assetList = []*assetListItem{&assetListItem{
			name:       customListURL,
			content:    "custom",
			group:      "custom",
			contentURL: customListURL,
		}}
	}


	return nil
}

func parseLine(line string, foriOS bool) (r *rawGraphElement, e error) {
	var tokens []string
	if foriOS {
		tokens = pEntryIOS.FindStringSubmatch(line)
	} else {
		tokens = pEntry.FindStringSubmatch(line)
	}

	/// check for full match, as in the whole pattern is matched, aka use only the formats supported
	if tokens == nil {
		return nil, fmt.Errorf("unrecognized format [%s]", line)
	}
	if tokens[0] == "" {
		return nil, fmt.Errorf("unhandled format [%s]", line)
	}

	r = &rawGraphElement{}
	var err error
	/// can't handle fine grained filters as of yet
	if tokens[9] != "" {
		if foriOS {
			//log("Options: [%s]\n", tokens[9])
			if r.opts, err = newFilterOptions(tokens[9]); err != nil {
				//log("Aborting construction of element due to Opts error: [%s]\n", err.Error())
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("cannot handle options [%s]", tokens[9])
		}
	}

	if tokens[10] != "" {
		if foriOS {
			//log("CSS selectors: [%s]\n", tokens[10])
			r.domfilter = tokens[10]
		} else {
			return nil, fmt.Errorf("cannot handle DOM alteration")
		}
	}

	if foriOS && tokens[11] != "" {
		//log("CSS exception selectors: [%s]\n", tokens[10])
		r.domexception = tokens[11]
	}

	if foriOS && tokens[12] != "" {
		return nil, fmt.Errorf("cannot handle exntended/ABP css selectors")
	}

	if tokens[2] != "" {
		r.flags |= flagException
	}
	/// host entry
	if tokens[3] != "" {
		r.token = tokens[3]
		r.flags |= flagDoublePipe
	} else
	/// fixed domain
	if tokens[5] != "" {
		r.token = tokens[5]
		// DANGER DANGER!!!!!
		r.flags |= flagDoublePipe
	}
	/// url part or fixed end/start
	if tokens[7] != "" {
		if tokens[6] != "" {
			r.flags |= flagPipeStart
		}
		if tokens[8] != "" {
			r.flags |= flagPipeEnd
		}
		r.token = tokens[7]
	}

	if strings.Contains(r.token, "*") {
		r.flags |= flagWildCard
	}
	if strings.Contains(r.token, "^") {
		r.flags |= flagSeparator
	}
	r.original = r.token

	//log("LINE::[%v]\n", tokens)

	return r, nil
}

func constructFilter() (ret sortableGraphInput, e error) {
	assetText := ""
	var assetTextB []byte
	var lineEndToken string
	var g *rawGraphElement
	ret = make(sortableGraphInput, 0)
	for _, a := range assetList {
		lineEndToken = "\n"
		log("Loading ASSET [%s][%s]\n", a.name, a.contentURL)
		if a.name != "asbexception" {
			if assetText, e = fetchText(a.contentURL); e != nil {
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
		if strings.Contains(assetText, "\r\n") {
			lineEndToken = "\r\n"
		}
		lines := strings.Split(assetText, lineEndToken)
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
						ret = append(ret, &rawGraphElement{tempTok, g.suffix, g.flags, g.original, g.filter, nil,"",""})
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
		if compileDebugAsset {
			d.Insert(input.token, &ubDebugPayload{ubPayload: &ubPayload{flags: input.flags, suffix: input.suffix}, list: input.filter, original: input.original})
		} else if input.flags != 0 {
			d.Insert(input.token, &ubPayload{flags: input.flags, suffix: input.suffix})
		} else {
			d.Insert(input.token, nil)
		}
	}
	d.Finish()
	log("Constructed. [%d] and [%d] are the stats, out of [%d]/[%d] characters\n", d.EdgeCount(), d.NodeCount(), charCount, wcCount)
	log("Flushing graph asset to %s\n\n", assetFilename)
	c := d.Serialize(assetFilename)

	test := UBlockHelper{}
	test.Deserialize(c)
	time.Sleep(2 * time.Second)
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
		"https://sp.analytics.yahoo.com/sp.pl?a=10000&d=Fri%2C%2005%20Mar%202021%2005%3A14%3A48%20GMT&n=-2&ea=page_view"}
	for _, t := range tests {
		st := time.Now()
		ret, _ := test.Search(t)
		//ret, _ := plainSearch(d, t)
		log("Test is [%v] -- [%v] [%s]\n\n", time.Now().Sub(st), ret, t)//, graph.MatchStatusToString[res.MatchStatus], res.Remainder, res.Payload)
	}

	return uniqueRet, nil
}

func constructFilterJSON() (e error) {
	assetText := ""
	var lineEndToken string
	var g *rawGraphElement
	ret := make([]*iosFilterElement, 0)

	dedup := make(map[string]bool)

	exceptionNum := 0

	for _, a := range assetList {
		lineEndToken = "\n"
		log("Loading ASSET [%s][%s]\n", a.name, a.contentURL)
		if assetText, e = fetchText(a.contentURL); e != nil {
			log("Cannot load asset [%s] - [%s]\n", a.name, e.Error())
			continue
		}
		if strings.Contains(assetText, "\r\n") {
			lineEndToken = "\r\n"
		}
		lines := strings.Split(assetText, lineEndToken)
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
				toAdd := &iosFilterElement{Original: l, File: a.name}

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

				toAdd.Trigger = &iosFilterTrigger{
					URLFilter:    g.token,
					IfDomain:     nil,
					UnlessDomain: nil,
					ResourceType: nil,
					LoadType:     nil,
					IfTopURL:     nil,
					UnlessTopURL: nil,
				}

				toAdd.Action = &iosFilterAction{
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
					if g.opts.opts["subdocument"] || g.opts.opts["document"] || g.opts.opts["frame"]{
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
					} else if tp == true {
						toAdd.Trigger.LoadType = append(toAdd.Trigger.LoadType, "third-party")
					} else if fp == true {
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









	partitionedRet := [][]*iosFilterElement{}
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


// AssembleRuleDatabase - called construction-time on an initialized package to construct, and export uBlock graph asset
func AssembleRuleDatabase(forIOS bool) (e error) {
	if e = constructAssetList(forIOS); e != nil {
		return e
	}
	if !forIOS {
		_, e = constructFilter()
	} else {
		e = constructFilterJSON()
	}
	if e != nil {
		return e
	}
	return nil
}
