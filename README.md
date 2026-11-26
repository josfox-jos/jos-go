# `jos.mx/jos` — Official Go SDK & CLI for `.jos`

Official Go library and CLI for **`.jos` (JSON Operating System)** — RFC 8785 JCS canonicalization, SHA-256 content-addressed sealing (`art_<hex>`), and structural `.jos 2.0` verification.

## Install

```bash
go get jos.mx/jos@v0.1.0
go install jos.mx/jos/cmd/jos@v0.1.0
```

## Quick Start

```go
package main

import (
    "fmt"
    "jos.mx/jos"
)

func main() {
    doc := map[string]any{
        "jos":  map[string]any{"version": "2.0.0", "kind": "atom"},
        "meta": map[string]any{"name": "example", "version": "0.1.0"},
    }
    sealed, artID, _ := jos.Seal(doc)
    fmt.Println(artID, len(sealed))
}
```

## Links

- Specification & Validator: https://jos.mx
- JOSFOX Cloud Vault & AI Hub: https://josfox.cloud

## License

Apache-2.0
