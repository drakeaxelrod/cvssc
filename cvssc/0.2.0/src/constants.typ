// CVSS Calculator Constants
// Centralized configuration for colors, specifications, and other constants

// ============================================================================
// SEVERITY COLORS
// ============================================================================

/// Severity color palette
/// Used for badges, graphs, and visual indicators
#let severity-colors = (
  "none": rgb("#0366d6"),      // Blue
  "low": rgb("#28a745"),       // Green
  "medium": rgb("#f66a0a"),    // Orange
  "high": rgb("#d73a49"),      // Red
  "critical": rgb("#6f42c1"),  // Purple
)

// ============================================================================
// CHART COLORS
// ============================================================================

/// Chart visualization colors
#let chart-colors = (
  "chart-grid": rgb("#9ca3af"),      // Darker gray for grid lines
  "chart-text": rgb("#475569"),      // Dark gray for text labels
  "chart-bg": none,                  // Transparent background
)

// ============================================================================
// SPECIFICATION URLS
// ============================================================================

/// Official CVSS specification document URLs
#let specifications = (
  "2.0": "https://www.first.org/cvss/v2/guide",
  "3.0": "https://www.first.org/cvss/v3.0/specification-document",
  "3.1": "https://www.first.org/cvss/v3.1/specification-document",
  "4.0": "https://www.first.org/cvss/v4.0/specification-document",
)

// ============================================================================
// SEVERITY RATING THRESHOLDS
// ============================================================================

/// Get severity rating from numeric score
///
/// - score (number): CVSS score (0-10)
/// -> string: Severity level (none, low, medium, high, critical)
#let get-severity-from-score(score) = {
  if score == none or score == 0 {
    "none"
  } else if score <= 3.9 {
    "low"
  } else if score <= 6.9 {
    "medium"
  } else if score <= 8.9 {
    "high"
  } else {
    "critical"
  }
}
