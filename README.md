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

* nav bar
* file listings
* delete the left column
* struct fields
* follow imports for better categorization
* doctests
* setting for displaying private parts
* markdown
* convert TODO comments into roadmap
