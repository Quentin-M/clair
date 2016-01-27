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

package v1

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/coreos/clair/api/context"
)

func postLayer(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	return 0
}
func getLayer(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	return 0
}
func deleteLayer(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	return 0
}

func getNamespaces(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	return 0
}

func postVulnerability(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	return 0
}
func getVulnerability(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	return 0
}
func patchVulnerability(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	return 0
}
func deleteVulnerability(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	return 0
}

func postFix(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	return 0
}
func getFixes(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	return 0
}
func putFix(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	return 0
}
func deleteFix(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	return 0
}

func getNotification(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	return 0
}
func deleteNotification(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	return 0
}

func getMetrics(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *context.RouteContext) int {
	prometheus.Handler().ServeHTTP(w, r)
	return 0
}
