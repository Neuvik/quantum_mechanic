# EAM Classification Templates — Attribution

The JSON classification templates in this directory are derivative works based on
data from the **EntraOps** project by Thomas Naunheim (Cloud-Architekt).

## Source

- **Project:** `Cloud-Architekt/EntraOps`
- **Repository:** https://github.com/Cloud-Architekt/EntraOps
- **Copyright holder:** Thomas Naunheim (Cloud-Architekt)
- **License:** MIT

## Source Files Used

The following upstream files were used as source data:

- `Classification/Templates/Classification_AadResources.json`
- `Classification/Templates/Classification_ApiPermissions.json`

## Modifications

The upstream data has been **flattened and filtered** from its original nested
template format into the simplified per-resource JSON files used by Quantum
Mechanic (`directory_roles.json`, `graph_permissions.json`, `role_actions.json`).
No classification values, tier labels, or semantic content were altered — only
the structural layout was changed to suit this project's loader.

## Upstream License (MIT)

```
MIT License

Copyright (c) 2024 Thomas Naunheim

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
