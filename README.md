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

* Walk: for_range not handled correctly
* root package alias - avoid `std.std` from ocurring
* implement alias for `const a = b;`
* implement alias for `const a = b.c;`
* source view: implement scrolling to local var decls
* source view: implement redirect when decl found
* doctests
* don't redundantly show doc comments in struct fields
* functions + ability to expand source of only that function without leaving the page
* add source view links, currently you have to use the keyboard shortcut
* include struct field names and doc comments in search query matching
* include function parameter names and doc comments in search query matching
* follow imports for better categorization
* setting for displaying private parts
* markdown
* convert TODO comments into roadmap
* only change URL on pressing enter in search box, not on key press
* scroll to top when clicking fresh link. but don't disrupt the already working scroll history
