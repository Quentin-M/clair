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
	"time"

	"github.com/julienschmidt/httprouter"
)

// VersionRouter is an HTTP router that forwards requests to the appropriate
// router depending on the API version specified in the requested URI.
type VersionRouter map[string]*httprouter.Router

// NewVersionRouter instantiates a VersionRouter and every sub-routers that are
// necessary to handle supported API versions.
func NewVersionRouter(to time.Duration, env *Env) *VersionRouter {
	return &VersionRouter{
		"/v1": NewRouterV1(to, env),
	}
}

// ServeHTTP forwards requests to the appropriate router depending on the API
// version specified in the requested URI and remove the version information
// from the request URL.Path, without modifying the request uRequestURI.
func (vs VersionRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	urlStr := r.URL.String()
	var version string
	if len(urlStr) >= 3 {
		version = urlStr[:3]
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

// NewRouterV1 creates a new router for the API (Version 1)
func NewRouterV1(to time.Duration, env *Env) *httprouter.Router {
	router := httprouter.New()
	wrap := func(fn Handler) Handler {
		return Logger(TimeOut(to, fn))
	}

	// General
	router.GET("/versions", wrap(GETVersions))
	router.GET("/health", wrap(GETHealth))

	// Layers
	router.POST("/layers", wrap(POSTLayers))
	router.DELETE("/layers/:id", wrap(DELETELayers))
	router.GET("/layers/:id", wrap(GETLayers))

	// Vulnerabilities
	// router.POST("/vulnerabilities", wrap(logic.POSTVulnerabilities))
	// router.PUT("/vulnerabilities/:id", wrap(logic.PUTVulnerabilities))
	// router.GET("/vulnerabilities/:id", wrap(logic.GETVulnerabilities))
	// router.DELETE("/vulnerabilities/:id", wrap(logic.DELVulnerabilities))
	// router.GET("/vulnerabilities/:id/introducing-layers", wrap(logic.GETVulnerabilitiesIntroducingLayers))
	// router.POST("/vulnerabilities/:id/affected-layers", wrap(logic.POSTVulnerabilitiesAffectedLayers))

	return router
}

// NewHealthRouter creates a new router that only serve the Health function on /
func NewHealthRouter(env *Env) *httprouter.Router {
	router := httprouter.New()
	router.GET("/", GETHealth)
	return router
}
