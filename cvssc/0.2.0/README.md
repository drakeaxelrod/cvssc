# CVSS Calculator for Typst

A comprehensive Typst library for calculating Common Vulnerability Scoring System (CVSS) scores across all major versions.

**Supports CVSS v2.0, v3.0, v3.1, and v4.0** - the complete suite of CVSS standards.

Based on official specifications from [FIRST.org](https://www.first.org/cvss/).

## Installation

```typst
#import "@preview/cvssc:0.2.0": *
```

## Quick Start

```typst
// Auto-detect version and calculate
#let result = calc("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
Score: #result.overall-score  // 9.8
Severity: #result.severity    // "CRITICAL"

// Display as colored badge
#cvss-display("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
```

## Supported Versions

### CVSS 2.0
- Base Metrics: AV, AC, Au, C, I, A
- Temporal Metrics: E, RL, RC
- Environmental Metrics: CDP, TD, CR, IR, AR
- Severity: LOW, MEDIUM, HIGH

### CVSS 3.0
- Base Metrics: AV, AC, PR, UI, S, C, I, A
- Temporal Metrics: E, RL, RC
- Environmental Metrics: CR, IR, AR, MAV, MAC, MPR, MUI, MS, MC, MI, MA
- Severity: NONE, LOW, MEDIUM, HIGH, CRITICAL

### CVSS 3.1
- Same as CVSS 3.0 with refined environmental score calculation
- Most widely used version
- Severity: NONE, LOW, MEDIUM, HIGH, CRITICAL

### CVSS 4.0
- Base Metrics: AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA
- Threat Metrics: E
- Environmental Metrics: CR, IR, AR, MAV, MAC, MAT, MPR, MUI, MVC, MVI, MVA, MSC, MSI, MSA
- Supplemental Metrics: S, AU, R, V, RE, U
- Uses macro vector system for scoring
- Severity: NONE, LOW, MEDIUM, HIGH, CRITICAL

## Usage Examples

### Auto-Detection (Recommended)

The `calc()` function automatically detects the CVSS version:

```typst
// CVSS 2.0
#let r1 = calc("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P")

// CVSS 3.1
#let r2 = calc("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

// CVSS 4.0
#let r3 = calc("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
```

### Version-Specific Functions

```typst
// CVSS 2.0
#let score = v2("CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C")

// CVSS 3.0 or 3.1
#let score = v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

// CVSS 4.0
#let score = v4("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
```

### Dictionary Format

```typst
#let result = calc((
  version: "3.1",
  metrics: (
    "AV": "N", "AC": "L", "PR": "N", "UI": "N",
    "S": "U", "C": "H", "I": "H", "A": "H"
  )
))
```

### String Conversion

```typst
// Parse CVSS string to dictionary
#let vec = str2vec("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
// vec.version => "3.1"
// vec.metrics => ("AV": "N", "AC": "L", ...)

// Convert dictionary back to string
#let str = vec2str((
  version: "3.1",
  metrics: ("AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H")
))
```

## Display Functions

### Score Badge

```typst
#cvss-display("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
```

Shows colored badge: **CRITICAL 9.8**

### Badge with Vector

```typst
#cvss-display("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", show-vector: true)
```

### Detailed Score Breakdown

```typst
#cvss-detailed("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
```

Shows table with base, temporal, environmental, and overall scores.

### Metrics Breakdown

```typst
#cvss-metrics("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
```

Shows table with all metric names and values.

## CVSS Vector Formats

### CVSS 2.0 Format

```
CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P
```

**Base Metrics:**
- AV (Access Vector): L, A, N
- AC (Access Complexity): H, M, L
- Au (Authentication): M, S, N
- C (Confidentiality Impact): N, P, C
- I (Integrity Impact): N, P, C
- A (Availability Impact): N, P, C

**Temporal Metrics:**
- E (Exploitability): U, POC, F, H, ND
- RL (Remediation Level): OF, TF, W, U, ND
- RC (Report Confidence): UC, UR, C, ND

### CVSS 3.x Format

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

**Base Metrics:**
- AV (Attack Vector): N, A, L, P
- AC (Attack Complexity): L, H
- PR (Privileges Required): N, L, H
- UI (User Interaction): N, R
- S (Scope): U, C
- C (Confidentiality Impact): N, L, H
- I (Integrity Impact): N, L, H
- A (Availability Impact): N, L, H

**Temporal Metrics:**
- E (Exploit Code Maturity): X, U, P, F, H
- RL (Remediation Level): X, O, T, W, U
- RC (Report Confidence): X, U, R, C

### CVSS 4.0 Format

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
```

**Base Metrics:**
- AV (Attack Vector): N, A, L, P
- AC (Attack Complexity): L, H
- AT (Attack Requirements): N, P  *(NEW)*
- PR (Privileges Required): N, L, H
- UI (User Interaction): N, P, A
- VC (Vulnerable System Confidentiality): H, L, N
- VI (Vulnerable System Integrity): H, L, N
- VA (Vulnerable System Availability): H, L, N
- SC (Subsequent System Confidentiality): H, L, N  *(NEW)*
- SI (Subsequent System Integrity): H, L, N, S  *(NEW)*
- SA (Subsequent System Availability): H, L, N, S  *(NEW)*

**Threat Metrics:**
- E (Exploit Maturity): X, U, P, A

## Severity Ratings

| Score Range | CVSS 2.0 | CVSS 3.x / 4.0 |
|-------------|----------|----------------|
| 0.0         | -        | NONE           |
| 0.1 - 3.9   | LOW      | LOW            |
| 4.0 - 6.9   | MEDIUM   | MEDIUM         |
| 7.0 - 8.9   | HIGH     | HIGH           |
| 9.0 - 10.0  | HIGH     | CRITICAL       |

## Real-World Examples

### CVE-2021-44228 (Log4Shell)

```typst
// CVSS 3.1
#cvss-display("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
// Result: CRITICAL 10.0
```

### CVE-2014-0160 (Heartbleed)

```typst
// CVSS 2.0
#cvss-display("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:N/A:N")
// Result: MEDIUM 5.0

// CVSS 3.1
#cvss-display("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
// Result: HIGH 7.5
```

## API Reference

### Main Functions

#### `calc(vec) -> dict`
Calculate CVSS scores with auto-version detection.
- **Input**: String (vector) or dictionary
- **Returns**: Dictionary with scores, severity, and metadata

#### `v2(vec) -> dict`
Calculate CVSS 2.0 scores.

#### `v3(vec) -> dict`
Calculate CVSS 3.0 or 3.1 scores.

#### `v4(vec) -> dict`
Calculate CVSS 4.0 scores.

### Utility Functions

#### `str2vec(s) -> dict`
Parse CVSS string to dictionary with `version` and `metrics` fields.

#### `vec2str(vec) -> string`
Convert CVSS dictionary to string.

#### `get-version(input) -> string`
Extract version from CVSS string.

### Display Functions

#### `cvss-display(vector-string, show-vector: false) -> content`
Display CVSS score as colored badge.

#### `cvss-detailed(vector-string) -> content`
Display detailed score breakdown table.

#### `cvss-metrics(vector-string) -> content`
Display all metrics and values table.

### Return Format

All calculation functions return a dictionary with kebab-case keys:

```typst
(
  version: "3.1",
  base-score: 9.8,
  temporal-score: none,
  environmental-score: none,
  overall-score: 9.8,
  severity: "CRITICAL",
  base-severity: "CRITICAL",
  metrics: ("AV": "N", "AC": "L", ...),
  specification-document: "https://..."
)
```

CVSS 4.0 also includes:
- `threat-score`: Threat score (if applicable)
- `macro-vector`: 6-digit macro vector string (e.g., "000020")

## Key Differences Between Versions

### CVSS 2.0 → 3.0
- Added **Scope** metric
- Changed "Authentication" to "Privileges Required"
- Impact values: Partial → Low, Complete → High
- Added **CRITICAL** severity rating
- More granular scoring

### CVSS 3.0 → 3.1
- Refined environmental score calculation
- One formula difference in Modified Impact calculation
- Otherwise identical

### CVSS 3.1 → 4.0
- **Revolutionary change**: Macro vector system replaces formulas
- Added **Attack Requirements** (AT)
- Replaced Scope with **Subsequent System** impacts (SC, SI, SA)
- Simplified temporal metrics
- Added supplemental metrics for context
- Equivalent Class (EQ) system for scoring

## License

MIT License

## References

- [CVSS v2.0 Guide](https://www.first.org/cvss/v2/guide)
- [CVSS v3.0 Specification](https://www.first.org/cvss/v3.0/specification-document)
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [CVSS v4.0 Specification](https://www.first.org/cvss/v4.0/specification-document)
- Inspired by [metaeffekt Universal CVSS Calculator](https://github.com/org-metaeffekt/metaeffekt-universal-cvss-calculator)

## Contributing

Contributions welcome! This library implements all official CVSS specifications in pure Typst.
