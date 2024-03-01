# Zig Documentation Generator

Creates an interactive, searchable, static web application for presenting Zig
package documentation.

## Status

It's at the proof-of-concept stage. Not polished yet.

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
and put it also into `zig-out/`.

## Roadmap

* source view - resolve single identifier lookups using in-scope names
  - if it targets an alias then jump to the alias
  - if it is field access then resolve the alias of the LHS
* source view - resolve identifier links to locals to link to the local decl
* source view - newlines showing up in links
* source view - make identifier links style subtler so it still looks like source
* nav bar
* detect if it's the root package file and skip the top of the nav
* delete the left column
* struct fields
* follow imports for better categorization
* doctests
* setting for displaying private parts
* markdown
* convert TODO comments into roadmap
