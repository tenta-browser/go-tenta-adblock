package ublock

import (
	"crypto/md5"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ASSET CACHE

type assetCacheEntry struct {
	filepath string    // path and filename
	exp      time.Time // expiration date
}

type assetCache struct {
	entries map[string]*assetCacheEntry // file list
	ttl     time.Duration               // default TTL for newly created files
	dir     string                      // working directory
	m       sync.Mutex
}

func newAssetCache(dir string, ttl time.Duration) (*assetCache, error) {
	c := &assetCache{
		ttl: ttl,
		dir: dir,
	}

	if err := c.refresh(); err != nil {
		return nil, err
	}

	return c, nil
}

// refresh lists all the files from `dir` and creates a new index.
// is a file is expired it will be removed from filesystem
func (c *assetCache) refresh() error {
	c.m.Lock()
	defer c.m.Unlock()

	fid, e := ioutil.ReadDir(c.dir)
	if e != nil {
		log("readdir err [%s]\n", e.Error())
		return e
	}

	entries := make(map[string]*assetCacheEntry)

	for _, fi := range fid {
		if fi.IsDir() {
			continue
		}

		// file names must follow the format: <md5_sum>_<unix_timestamp>
		sub := strings.Split(fi.Name(), "_")
		if len(sub) != 2 {
			continue
		}

		// check for valid md5
		if !isMD5(sub[0]) {
			continue
		}

		// validate timestamp
		i, err := strconv.ParseInt(sub[1], 10, 64)
		if err != nil {
			continue
		}

		// check if file is expired
		t := time.Unix(i, 0)
		if time.Now().After(t) {
			log("asset cache: removing expired cache file [%s]\n", fi.Name())
			os.Remove(filepath.Join(c.dir, fi.Name()))
			continue
		}

		entries[sub[0]] = &assetCacheEntry{
			filepath: filepath.Join(c.dir, fi.Name()),
			exp:      t,
		}
	}

	c.entries = entries
	return nil
}

// addCachesAsset adds the file to index and writes the data to filesystem
func (c *assetCache) add(name string, data []byte) error {
	c.m.Lock()
	defer c.m.Unlock()

	k := md5Sum(name)
	e := &assetCacheEntry{
		exp: time.Now().Add(c.ttl),
	}
	e.filepath = filepath.Join(c.dir, fmt.Sprintf("%s_%d", k, e.exp.Unix()))
	c.entries[k] = e

	return ioutil.WriteFile(e.filepath, data, 0755)
}

// get returns the file's content.
// If the file is found to be expired, it will be removed from filesystem
func (c *assetCache) get(name string) ([]byte, error) {
	k := md5Sum(name)

	e, ok := c.entries[k]
	if !ok {
		return nil, nil
	}

	if time.Now().After(e.exp) {
		delete(c.entries, k)
		os.Remove(e.filepath)
		return nil, nil
	}

	return ioutil.ReadFile(e.filepath)
}

func isMD5(s string) (ret bool) {
	ret, _ = regexp.MatchString(`^[a-f0-9]{32}$`, s)
	return
}

func md5Sum(s string) string {
	h := md5.New()
	io.WriteString(h, s)

	return fmt.Sprintf("%x", h.Sum(nil))
}
