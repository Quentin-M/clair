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

// Package detectors exposes functions to register and use container
// information extractors.
package detectors

import (
	"fmt"
	"sync"
)

// The NamespaceDetector interface defines a way to detect an Operating System and
// its version from input data.
type NamespaceDetector interface {
	// Detect detects an Operating System and its version from input data.
	Detect(map[string][]byte) string
	// GetRequiredFiles returns the list of files required for Detect, without
	// leading /.
	GetRequiredFiles() []string
}

var (
	namespaceDetectorsLock sync.Mutex
	namespaceDetectors     = make(map[string]NamespaceDetector)
)

// RegisterNamespaceDetector provides a way to dynamically register an implementation of a
// NamespaceDetector.
//
// If RegisterNamespaceDetector is called twice with the same name if NamespaceDetector is nil,
// or if the name is blank, it panics.
func RegisterNamespaceDetector(name string, f NamespaceDetector) {
	if name == "" {
		panic("Could not register a NamespaceDetector with an empty name")
	}
	if f == nil {
		panic("Could not register a nil NamespaceDetector")
	}

	namespaceDetectorsLock.Lock()
	defer namespaceDetectorsLock.Unlock()

	if _, alreadyExists := namespaceDetectors[name]; alreadyExists {
		panic(fmt.Sprintf("Detector '%s' is already registered", name))
	}
	namespaceDetectors[name] = f
}

// DetectNamespace finds the OS of the layer by using every registered NamespaceDetector.
func DetectNamespace(data map[string][]byte) string {
	for _, detector := range namespaceDetectors {
		if namespace := detector.Detect(data); namespace != "" {
			return namespace
		}
	}

	return ""
}

// GetRequiredFilesOS returns the list of files required for DetectNamespace for every
// registered NamespaceDetector, without leading /.
func GetRequiredFilesNamespace() (files []string) {
	for _, detector := range namespaceDetectors {
		files = append(files, detector.GetRequiredFiles()...)
	}

	return
}
