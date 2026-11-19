# The libraries in this directory

The library is built with two others, and this directory holds a copy of
each. A copy can be changed here, and a change can be tried against the
tests of this repository and against the tests of the copy. The lines of
a TLA+ model can stand in a copy's source, beside the code that they are
about: `tools/tla` reads them there as it reads them in `src`.

| Directory | Project | Commit | Tree | License |
| --- | --- | --- | --- | --- |
| `smoltcp` | [smoltcp](https://github.com/smoltcp-rs/smoltcp) | `c68ace42306fa6a31b7d3c893043829587a9c7a8` | `ab3e77b748e73c59b035d8734ce13d4d43b29600` | 0BSD, in `smoltcp/LICENSE-0BSD.txt` |
| `boringtun` | [boringtun](https://github.com/cloudflare/boringtun) | `051c9d47dc9c5cb36e461b7d36dcd673820dc98b` | `d16ca4e148aabdc77395f73b0bec5ff5412ee009` | BSD 3-Clause, in `boringtun/LICENSE.md` |

A copy is the tree of its project at the commit that the table gives,
with the deviations that are set out below. Tree is the hash that git
has for that tree. The commit of boringtun is its release 0.7.1.
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

## Deviations

A change that this repository makes to a copy is a deviation. A
deviation has a name, and it has a class, which says what is to become
of it. This is the table of deviations, which lists them all, and the
table of classes follows it.

| Copy | Deviation | Class | What it changes |
| --- | --- | --- | --- |
| `smoltcp` | `receive-window` | `fix` | A socket takes a segment as far as any edge of the receive window that it advertised, and passes over the FIN of a segment that it cut there. |
| `smoltcp` | `ring-debug` | `fix` | The `Debug` of a ring buffer leaves out the elements of its storage. That of a TCP socket wrote every octet of its two buffers. |
| `smoltcp` | `sends-now` | `addition` | `Socket::sends_now` says whether a socket has a segment to send at once. |
| `smoltcp` | `lock` | `build` | `Cargo.lock` names the crates that the tests of smoltcp are built with here. |
| `boringtun` | `confirmed-session` | `fix` | A tunnel sends in the session that the peer has shown it holds the keys of, and counts the time since a handshake from that one. It took whatever session was in that place of its ring. |

| Class | What a deviation of the class is |
| --- | --- |
| `backport` | A commit that the project has, later than the commit of the copy. It goes when the copy moves to a commit that has it. |
| `fix` | It mends a fault of the project, and the project can be offered it. |
| `addition` | It adds what the project does not have, and the project can be offered it. |
| `local` | It makes the copy fit this library in a way that the project would not want. |
| `build` | It changes what the copy is built with or tested with, and not the source. |
| `model` | The lines of the TLA+ models. A line has this class by its form, which is `// TLA-NAME>` and what follows. The table above does not list them. |

A commit that changes a copy keeps these rules:

- The commit is part of one deviation, and a trailer of its message
  names it, as in `Deviation: receive-window`. A later commit that adds
  to the deviation has the same trailer.
- The commit changes nothing outside the copy but the table of
  deviations, where the first commit of a deviation adds its row. The subject begins with
  the name of the copy and a colon, and the message is written for the
  project. So the project can be offered the commit as it is. What this
  library then does with the change is another commit.
- The lines of a model are apart from that. Any commit can put them
  into a copy or change them there, and needs no trailer for them. A
  model changes with the code of this library that it describes, in one
  commit, and that commit can then change the lines in a copy too.
- The deviations can be made again on the tree of the project, in the
  order that the table of classes has, and that makes the copy as it
  is. So a deviation that the project could take never rests on one
  that it would not take. The class of a deviation can be changed in
  its row for as long as this holds.

`tools/deviations check` holds the history and the table to the rules,
and CI runs it. CI also has rustfmt check each copy with its default
settings, as the checks of each project do, so that a deviation is laid
out as its project wants. `rake deviations` runs both. Two commits changed the copy of smoltcp before there
were rules, and each also changed files of this library. The tool names
the two.

```bash
tools/deviations
tools/deviations fix addition
tools/deviations show sends-now
tools/deviations patches tmp/deviations
```

With no argument, the tool lists the deviations of each copy by class.
Each has its line of the table, the lines that it adds and removes, and
its files. With classes, it lists those alone. `show` prints one
deviation as one patch. `patches` writes a file for each deviation, in
the order of the classes. The paths in a patch are those of the project,
and the lines of the models are not in it, so `git am` takes the file in
a clone of the project. The lines of the models are a file of their own,
which is the last.

The tool takes the commit that a copy came in with to be the newest
commit at which the directory has the tree of the table of copies. That
commit changed nothing of the copy: the hash is the one that
`git rev-parse COMMIT^{tree}` prints in a clone of the project. All
that came after is in the list.

## Tests

`rake vendored` runs the tests that each project has of its own: the
library tests of smoltcp with its default features, and the tests of
boringtun with its default features, which leave out those that need a
TUN device. It runs the tests of boringtun once more with the feature
`mock-instant`, which has them move a clock of their own. CI runs them on each push. A deviation brings its tests in
the manner of the project, and they run there.

The file `smoltcp/Cargo.lock` is not from smoltcp, which keeps no lock
file. It names the crates that the tests of smoltcp are built with
here, so that they are the same each time. It is the deviation `lock`.

## A newer commit of a project

Write the deviations as patches, put the new tree of the project in the
place of the copy in a commit of its own, and make the deviations again
on top of it:

```bash
copy=ext/sallyport/vendor/smoltcp
tools/deviations patches tmp/deviations
git rm -r -q $copy
git -C /a/clone/of/the/project archive NEW | (mkdir -p $copy && tar -x -C $copy)
git add -f $copy
git write-tree --prefix=$copy/
git commit
git am --directory=$copy tmp/deviations/smoltcp/*.patch
```

`git write-tree` prints the hash of the new tree, which is to be the
hash that `git rev-parse NEW^{tree}` prints in the clone. The commit
that brings the tree in also gives the table of copies the new commit
and the new hash. Leave out the file of a deviation that the project now
has, and take its row out of the table of deviations. Each of the other
files becomes one commit, which has the trailer of its deviation.
