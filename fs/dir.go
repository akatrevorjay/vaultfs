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
	"os"
	"path"
	"strings"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"github.com/Sirupsen/logrus"
	"github.com/hashicorp/vault/api"
	"golang.org/x/net/context"
)

type Node struct {
	inode uint64
	name  string

	//prefix string
	v *VaultFS
}

// Dir implements both Node and Handle for the prefix directory.
type Dir struct {
	Node

	//logic *api.Logical
}

func (d *Dir) String() string {
	return path.Join(d.prefix, d.name)
}

// Attr sets attrs on the given fuse.Attr
func (d *Dir) Attr(ctx context.Context, a *fuse.Attr) error {
	log := logrus.WithField("dir", d)
	log.Debug("handling Dir.Attr call")

	a.Inode = d.inode
	a.Mode = os.ModeDir | 0555
	return nil
}

// Lookup looks up a path
func (d *Dir) Lookup(ctx context.Context, name string) (fs.Node, error) {
	var abspath string = path.Join(d.String(), name)
	log := logrus.WithField("abspath", abspath)
	log.Debug("handling Dir.Lookup call")

	// TODO: handle context cancellation
	secret, err := d.logic.Read(abspath)
	if err != nil {
		log.WithError(err).Error("error reading key")
		return nil, fuse.EIO
	}

	if secret == nil {
		return nil, fuse.ENOENT
	}

	file := &File{
		Node: Node{
			inode: HashInode(abspath, fuse.DT_Dir),
			name:  name,

			prefix: d.prefix,
		},

		Secret: secret,
	}

	return file, nil
}

func (v *VaultFS) NewNode(abspath string, dt fuse.DirentType) (Node, error) {
	n := Node{
		inode: HashInode(abspath, fuse.DT_Dir),
		v: v,
	}
	return n, nil
}

func (v *VaultFS) NewDir(abspath string) (*Dir, error) {
	d := &Dir{
		Node: v.NewNode(abspath, fuse.DT_Dir),
	}
	return d, nil
}

func (v *VaultFS) NewFile(abspath string) (*File, error) {
	d := &File{
		Node: v.NewNode(abspath, fuse.DT_Dir),
	}
	return d, nil
}

func (d *Dir) listContents(ctx context.Context) (entries chan Node, err error) {
	var abspath string = d.String()
	log := logrus.WithField("dir", abspath).WithField("ctx", ctx)
	log.Debug("handling Dir.listContents call")

	go func() {
		secrets, err := d.logic.List(abspath)
		if err != nil {
			log.WithError(err).Error("error reading secrets")
			return nil, fuse.EIO
		}

		keys, _ := secrets.Data["keys"]

		var (
			key string
			dt fuse.DirentType
		)

		// Gross, vault. gross.
		for i := 0; i < len(secrets.Data["keys"].([]interface{})); i++ {
			key = secrets.Data["keys"].([]interface{})[i].(string)

			dt = fuse.DT_File
			if strings.HasSuffix(key, "/") {
				key = key[:len(key)-1]
				dt = fuse.DT_Dir
			}

			//node := ctx
			//switch dt {
			//case fuse.DT_Dir:
			//    d := v
			//    d := &Dir{
			//        Node: node,

			d := fuse.Dirent{
				Name:  key,
				Inode: HashInode(key, dt),
				Type:  dt,
			}

			entries = append(entries, d)
		}

	return entries, nil
}

// ReadDirAll returns a list of secrets
func (d *Dir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	var abspath string = d.String()
	log := logrus.WithField("dir", abspath)
	log.Debug("handling Dir.ReadDirAll call")

	secrets, err := d.logic.List(d.String())
	if err != nil {
		log.WithError(err).Error("error reading secrets")
		return nil, fuse.EIO
	}

	var entries []fuse.Dirent

	if secrets.Data["keys"] == nil {
		return entries, nil
	}

	var key string
	var dt fuse.DirentType
	for i := 0; i < len(secrets.Data["keys"].([]interface{})); i++ {
		key = secrets.Data["keys"].([]interface{})[i].(string)

		dt = fuse.DT_File
		if strings.HasSuffix(key, "/") {
			key = key[:len(key)-1]
			dt = fuse.DT_Dir
		}

		d := fuse.Dirent{
			Name:  key,
			Inode: HashInode(key, dt),
			Type:  dt,
		}

		entries = append(entries, d)
	}

	return entries, nil
}
