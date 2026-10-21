# Examples

- `client.cpp` - header-only wrapper (`include/blook/kchannel.hpp`) plus the
  full attach -> bootstrap -> map -> finish -> call -> detach flow. Plug your
  manual mapper into `MapDriver()`; the example prints the bootstrap fields and
  exits cleanly when no mapper is present, so it doubles as a compile test.
- `kdu` / `drv` / `drv-lite` plug their own mappers; `docs/integration.md` has
  the exact xmake snippets and the kernel handler registration code.

Build: `xmake -y` then `build/windows/x64/release/kchannel-example.exe`.
