// Copyright © 2016 Asteris, LLC
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

package fs

import (
	"encoding/json"

	"bazil.org/fuse"
	"github.com/Sirupsen/logrus"
	"github.com/hashicorp/vault/api"
	"golang.org/x/net/context"
)

// File implements Node and Handle
type File struct {
	Node

	Secret *api.Secret
}

func (f *File) getSize(ctx context.Context) (size uint64, err error) {
	content, err := f.Secret.ReadAll(ctx)
	if err != nil {
		logrus.WithError(err).Error("could not determine content length")
		return nil, err
	}

	size = uint64(len(content))
	return size, nil
}

// Attr returns attributes about this File
func (f *File) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Inode = f.inode
	a.Mode = 0444

	size, err := f.getSize(ctx)
	if err != nil {
		return fuse.EIO
	}

	a.Size = uint64(len(content))
	return nil
}

// ReadAll gets the content of this File
func (s *File) ReadAll(ctx context.Context) ([]byte, error) {
	return json.MarshalIndent(s, "", 2)
}
