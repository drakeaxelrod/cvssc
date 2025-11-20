// Sandbox testing file for cvssc library
#import "lib.typ": calc, v2, v3, v4, validate

#set page(paper: "a4", margin: 2cm)
#set text(size: 11pt)

= CVSS Calculator Sandbox

Test your CVSS vectors here.

== Example 1: Auto-detection

#let result = calc("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

*Version:* #result.version \
*Base Score:* #result.base-score \
*Severity:* #result.severity

#result.badge-with-score

== Example 2: Your tests below

// Add your test vectors here
