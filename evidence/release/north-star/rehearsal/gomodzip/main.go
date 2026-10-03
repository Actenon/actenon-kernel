// gomodzip: write the Go module proxy files (info, mod, zip) for a module
// directory at a given version, exactly as a module proxy would serve them.
// usage: gomodzip <module-path> <version> <src-dir> <proxy-root>
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/zip"
)

func main() {
	path, version, src, root := os.Args[1], os.Args[2], os.Args[3], os.Args[4]
	escaped, err := module.EscapePath(path)
	if err != nil {
		panic(err)
	}
	dir := filepath.Join(root, escaped, "@v")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		panic(err)
	}
	f, err := os.Create(filepath.Join(dir, version+".zip"))
	if err != nil {
		panic(err)
	}
	if err := zip.CreateFromDir(f, module.Version{Path: path, Version: version}, src); err != nil {
		panic(err)
	}
	f.Close()
	mod, err := os.ReadFile(filepath.Join(src, "go.mod"))
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(dir, version+".mod"), mod, 0o644); err != nil {
		panic(err)
	}
	info, _ := json.Marshal(map[string]string{"Version": version, "Time": time.Now().UTC().Format(time.RFC3339)})
	if err := os.WriteFile(filepath.Join(dir, version+".info"), info, 0o644); err != nil {
		panic(err)
	}
	list := filepath.Join(dir, "list")
	existing, _ := os.ReadFile(list)
	if err := os.WriteFile(list, append(existing, []byte(version+"\n")...), 0o644); err != nil {
		panic(err)
	}
	fmt.Println("wrote", dir, version)
}
