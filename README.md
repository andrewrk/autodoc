# Zig Documentation Generator

Creates an interactive, searchable, static web application for presenting Zig
package documentation.

## Status

It's at the proof-of-concept stage. Not feature complete, let alone polished.

However, based on these results, I expect this to be a better way forward than
a ZIR-based documentation generation system. This system already has source
listings for every file with links back to the API docs, for example.

## Development

While Firefox and Safari support are obviously required, I recommend Chromium
for development for one reason in particular:

[C/C++ DevTools Support (DWARF)](https://chromewebstore.google.com/detail/cc++-devtools-support-dwa/pdcpmagijalfljmkmjngeonclgbbannb)

This makes debugging Zig WebAssembly code a breeze.

After making changes to `src/` or `lib/`:

```
zig build
```

Use whatever local static file server you want to host the files:

```
cd zig-out
python -m http.server
```

Finally, create the tarball to serve as the input file, name it `sources.tar`,
and put it also into `zig-out/`. The system expects the top level of the
tarball to be the set of packages documented. So for the Zig standard library
you would do this: `tar cf std.tar std/`. Don't compress it; the idea is to
rely on HTTP compression.

I also suggest to omit test fixtures and test files. In other words, use the
set of files that zig installs to zig-out when you run `zig build`, which is
the same as the set of files that are provided on ziglang.org/download.

If the system doesn't find a file named "foo/root.zig" or "foo/foo.zig" it's going
to use the first file in the tar as the package root, which is probably not
what you want.

## Roadmap

* struct field doc comments
* type links in struct fields
* add source view links, currently you have to use the keyboard shortcut
* source view - resolve single identifier lookups using in-scope names
  - if it targets an alias then jump to the alias
  - if it is field access then resolve the alias of the LHS
* source view - resolve identifier links to locals to link to the local decl
* source view - newlines showing up in links
* source view - make identifier links style subtler so it still looks like source
* detect if it's the root package file and skip the top of the nav
* include struct fields in search query matching
* functions + ability to expand source of only that function without leaving the page
* follow imports for better categorization
* doctests
* setting for displaying private parts
* markdown
* convert TODO comments into roadmap
