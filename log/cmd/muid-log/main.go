// Copyright 2024 The Tessera authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// muid-log is Tessera's cmd/conformance/posix server (v1.0.4) with one addition, taken from Tessera's
// cmd/examples/posix-oneshot: a witness policy, so that a checkpoint is published only once the witnesses it names
// have cosigned it, and a limit on the body of /add. Entries are POSTed to /add; checkpoints and tiles are served as
// files (C2SP tlog-tiles).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
	"k8s.io/klog/v2"
)

var (
	storageDir        = flag.String("storage_dir", "", "Root directory to store log data.")
	listen            = flag.String("listen", "127.0.0.1:2025", "Address:port to listen on")
	privKeyFile       = flag.String("private_key", "", "Location of private key file. If unset, uses the contents of the LOG_PRIVATE_KEY environment variable.")
	witnessPolicyFile = flag.String("witness_policy_file", "", "(Optional) Path to the file containing the witness policy in the format described at https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/doc/policy.md")
	witnessTimeout    = flag.Duration("witness_timeout", tessera.DefaultWitnessTimeout, "Maximum time to wait for witness responses.")
)

// maxEntry is the longest entry a C2SP tlog-tiles entry bundle can hold: each is written after a 16-bit length.
const maxEntry = math.MaxUint16

func addCacheHeaders(value string, fs http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Cache-Control", value)
		fs.ServeHTTP(w, r)
	}
}

func main() {
	klog.InitFlags(nil)
	flag.Parse()
	ctx := context.Background()

	driver, err := posix.New(ctx, posix.Config{Path: *storageDir})
	if err != nil {
		klog.Exitf("Failed to construct storage: %v", err)
	}
	opts := tessera.NewAppendOptions().
		WithCheckpointSigner(getSignerOrDie()).
		WithCheckpointInterval(time.Second).
		WithCheckpointRepublishInterval(time.Minute).
		WithBatching(256, time.Second).
		WithAntispam(tessera.DefaultAntispamInMemorySize, nil)
	if *witnessPolicyFile != "" {
		p, err := os.ReadFile(*witnessPolicyFile)
		if err != nil {
			klog.Exitf("Failed to read witness policy file %q: %v", *witnessPolicyFile, err)
		}
		wg, err := tessera.NewWitnessGroupFromPolicy(p)
		if err != nil {
			klog.Exitf("Invalid witness policy file %q: %v", *witnessPolicyFile, err)
		}
		opts = opts.WithWitnesses(wg, &tessera.WitnessOptions{Timeout: *witnessTimeout})
	}
	appender, shutdown, _, err := tessera.NewAppender(ctx, driver, opts)
	if err != nil {
		klog.Exit(err)
	}

	http.HandleFunc("POST /add", func(w http.ResponseWriter, r *http.Request) {
		// No more than maxEntry bytes of a body are read, so a longer one is never held or passed to the appender.
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxEntry))
		if err != nil {
			var tooLong *http.MaxBytesError
			if errors.As(err, &tooLong) {
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		idx, err := appender.Add(r.Context(), tessera.NewEntry(b))()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(err.Error()))
			return
		}
		if _, err := fmt.Fprintf(w, "%d", idx.Index); err != nil {
			klog.Errorf("/add: %v", err)
		}
	})
	fs := http.FileServer(http.Dir(*storageDir))
	http.Handle("GET /checkpoint", addCacheHeaders("no-cache", fs))
	http.Handle("GET /tile/", addCacheHeaders("max-age=31536000, immutable", fs))
	http.Handle("GET /entries/", fs)

	server := &http.Server{Addr: *listen, Handler: http.DefaultServeMux, ReadHeaderTimeout: 5 * time.Second}
	if err := server.ListenAndServe(); err != nil {
		if err := shutdown(ctx); err != nil {
			klog.Exit(err)
		}
		klog.Exitf("ListenAndServe: %v", err)
	}
}

// Read log private key from file or environment variable
func getSignerOrDie() note.Signer {
	var privKey string
	if len(*privKeyFile) > 0 {
		k, err := os.ReadFile(*privKeyFile)
		if err != nil {
			klog.Exitf("Unable to get private key: %q", err)
		}
		privKey = string(k)
	} else {
		privKey = os.Getenv("LOG_PRIVATE_KEY")
		if len(privKey) == 0 {
			klog.Exit("Supply private key file path using --private_key or set LOG_PRIVATE_KEY environment variable")
		}
	}
	s, err := note.NewSigner(privKey)
	if err != nil {
		klog.Exitf("Failed to instantiate signer: %q", err)
	}
	return s
}
