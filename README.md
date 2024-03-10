# Zig Documentation Generator

Creates an interactive, searchable, static web application for presenting Zig
package documentation.

## Status

Nearly reached feature parity with previous implementation.

[Will be upstreamed soon](https://github.com/ziglang/zig/pull/19208)

See the roadmap below.

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
tarball to be the set of modules documented. So for the Zig standard library
you would do this: `tar cf std.tar std/`. Don't compress it; the idea is to
rely on HTTP compression.

I also suggest to omit test fixtures and test files. In other words, use the
set of files that zig installs to zig-out when you run `zig build`, which is
the same as the set of files that are provided on ziglang.org/download.

If the system doesn't find a file named "foo/root.zig" or "foo/foo.zig" it's going
to use the first file in the tar as the module root, which is probably not
what you want.

## Pre-Merge Roadmap

* render member functions better (e.g. bottom of std)
* implement view: functions that return types that end with `return struct`
* function view: parameters
* function view: render fn prototype each component separate rather than source rendering
* struct fields: render each component separate rather than via source rendering
* add source view links, currently you have to use the keyboard shortcut
* make the search box and nav bar stretch to fit the window
* redundant search results (search "format")
* convert TODO comments into roadmap

## Post-Merge Roadmap

* infer comptime_int constants (example: members of `#std.time`)
* when global const has a type of `type`, categorize it as a type despite its value
  - example: `std.DynLib` (requires patching to add type annotation)
* show abbreviated doc comments in types and namespaces listings
* show type function names as e.g. `ArrayList(T)`
* enum fields should not be linkified (example: `std.log.Level`)
* shrink Ast to fit the slices
* linkification of methods (example: `std.array_hash_map.ArrayHashMap.count`)
* navigating to source from a decl should scroll to the decl
* in source view, make `@imports` into links, but keep same syntax highlighting
* include struct field names and doc comments in search query matching
* include function parameter names and doc comments in search query matching
