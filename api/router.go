// Copyright 2015 clair authors
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

package api

import (
	"net/http"
	"strings"

	"github.com/coreos/clair/api2/context"
	"github.com/julienschmidt/httprouter"
)

// router is an HTTP router that forwards requests to the appropriate sub-router
// depending on the API version specified in the request URI.
type router map[string]*httprouter.Router

// Let's hope we never have more than 99 API versions.
const apiVersionLength = len("v99")

func newAPIHandler(ctx *context.RouteContext) http.Handler {
	router := make(Router)
	router["v1"] = v1.newRouter(ctx)
	return router
}

func (r router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	urlStr := r.URL.String()
	var version string
	if len(urlStr) >= apiVersionLength {
		version = urlStr[:apiVersionLength]
	}

	if router, _ := vs[version]; router != nil {
		// Remove the version number from the request path to let the router do its
		// job but do not update the RequestURI
		r.URL.Path = strings.Replace(r.URL.Path, version, "", 1)
		router.ServeHTTP(w, r)
		return
	}

	http.NotFound(w, r)
}

func newHealthHandler(ctx *context.RouteContext) http.Handler {
	router := httprouter.New()
	router.GET("/health", context.Handler(getHealth, ctx))
	return router
}
