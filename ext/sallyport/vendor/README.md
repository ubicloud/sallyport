# The libraries in this directory

The library is built with two others, and this directory holds a copy of
each. A copy can be changed here, and a change can be tried against the
tests of this repository and against the tests of the copy. The lines of
a TLA+ model can stand in a copy's source, beside the code that they are
about: `tools/tla` reads them there as it reads them in `src`.

| Directory | What it is a copy of | License |
| --- | --- | --- |
| `smoltcp` | [smoltcp](https://github.com/smoltcp-rs/smoltcp) at commit `c68ace42306fa6a31b7d3c893043829587a9c7a8` | 0BSD, in `smoltcp/LICENSE-0BSD.txt` |
| `boringtun` | [boringtun](https://github.com/cloudflare/boringtun) at commit `051c9d47dc9c5cb36e461b7d36dcd673820dc98b`, which is its release 0.7.1 | BSD 3-Clause, in `boringtun/LICENSE.md` |

smoltcp is at a commit and not at a release. Release 0.14.0 panics when
a peer fills a receive window whose edge the window scale rounded back,
and the fix is in no release yet. The crate of boringtun is the
directory `boringtun/boringtun`. The rest of that copy is there because
the license is in the root of boringtun's repository, and not in the
crate.

## Licenses

Each directory is under the license of the project that it is a copy of,
and holds that license. That is so for all that the directory holds:
what this repository changes or adds there is under the same license, so
that a change can be offered to its project as it is. The rest of the
repository is under the Apache License 2.0, in `LICENSE` at its root.

## What was changed

Each copy came in with one commit, which changed nothing of it. At that
commit, the tree that git has for the directory has the same hash as
the tree of the project's commit.

| Directory | Hash of the tree |
| --- | --- |
| `smoltcp` | `ab3e77b748e73c59b035d8734ce13d4d43b29600` |
| `boringtun` | `d16ca4e148aabdc77395f73b0bec5ff5412ee009` |

So these commands show that the copy came in whole, and then all that
this repository has changed in it:

```bash
copy=ext/sallyport/vendor/smoltcp
first=$(git log --diff-filter=A --format=%H -- $copy/Cargo.toml | tail -1)
git rev-parse $first:$copy
git diff $first HEAD -- $copy
```

The file `smoltcp/Cargo.lock` is not from smoltcp, which keeps no lock
file. It names the crates that the tests of smoltcp are built with
here, so that they are the same each time.

## Tests

`rake vendored` runs the tests that each project has of its own: the
library tests of smoltcp with its default features, and the tests of
boringtun with its default features, which leave out those that need a
TUN device. CI runs them on each push.

## A newer commit of a project

Keep what was changed, put the project's new tree in the place of the
copy in a commit of its own, and make the changes again on top of it:

```bash
git diff $first HEAD -- $copy > changes.patch
git rm -r -q $copy
git -C /a/clone/of/the/project archive NEW | (mkdir -p $copy && tar -x -C $copy)
git add -f $copy
git write-tree --prefix=$copy/
git commit
git apply --3way changes.patch
```

`git write-tree` prints the hash of the new tree, which is to be the
hash that `git rev-parse NEW^{tree}` prints in the clone. The table
above then takes the new commit and the new hash.
