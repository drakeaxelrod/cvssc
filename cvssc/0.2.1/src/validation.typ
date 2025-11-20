// CVSS Vector Validation Module
// Provides validation functions for CVSS vectors across all versions

#import "v2/components.typ" as v2-comp
#import "v3/components.typ" as v3-comp
#import "v4/components.typ" as v4-comp

// ============================================================================
// NORMALISATION
// ============================================================================

/// Normalise metric dictionary keys and values to uppercase
///
/// - metrics-dict (dictionary): Dictionary of metric key-value pairs
/// -> dictionary
#let normalise-metrics(metrics-dict) = {
  if type(metrics-dict) != dictionary {
    panic("normalise-metrics: Input must be a dictionary")
  }

  let normalised = (:)
  for (key, value) in metrics-dict {
    normalised.insert(upper(key), upper(str(value)))
  }
  normalised
}

// ============================================================================
// COMPONENT LOOKUPS
// ============================================================================

/// Get valid metric keys for a CVSS version
///
/// - version (string): CVSS version ("2.0", "3.0", "3.1", or "4.0")
/// -> array
#let get-valid-metrics(version) = {
  let components = if version == "2.0" {
    v2-comp.all-components
  } else if version == "3.0" or version == "3.1" {
    v3-comp.all-components
  } else if version == "4.0" {
    v4-comp.all-components
  } else {
    panic("get-valid-metrics: Unsupported CVSS version '" + version + "'")
  }

  components.map(c => upper(c.short))
}

/// Get valid values for a specific metric in a CVSS version
///
/// - version (string): CVSS version ("2.0", "3.0", "3.1", or "4.0")
/// - metric-key (string): The metric key (e.g., "AV", "AC")
/// -> array
#let get-valid-values(version, metric-key) = {
  let components = if version == "2.0" {
    v2-comp.all-components
  } else if version == "3.0" or version == "3.1" {
    v3-comp.all-components
  } else if version == "4.0" {
    v4-comp.all-components
  } else {
    panic("get-valid-values: Unsupported CVSS version '" + version + "'")
  }

  let metric-key-upper = upper(metric-key)

  // Find component with matching short key
  let component = components.find(c => upper(c.short) == metric-key-upper)

  if component == none {
    return ()
  }

  // Extract valid value keys from the component's values dictionary
  component.values.keys().map(k => upper(str(k)))
}

/// Get required base metrics for a CVSS version
///
/// - version (string): CVSS version ("2.0", "3.0", "3.1", or "4.0")
/// -> array
#let get-required-base-metrics(version) = {
  if version == "2.0" {
    ("AV", "AC", "AU", "C", "I", "A")
  } else if version == "3.0" or version == "3.1" {
    ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
  } else if version == "4.0" {
    ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")
  } else {
    panic("get-required-base-metrics: Unsupported CVSS version '" + version + "'")
  }
}

// ============================================================================
// VALIDATION FUNCTIONS
// ============================================================================

/// Validate that all metric keys exist in the CVSS specification
///
/// - metrics-dict (dictionary): Dictionary of metric key-value pairs (should be normalised)
/// - version (string): CVSS version ("2.0", "3.0", "3.1", or "4.0")
/// -> none (panics on validation failure)
#let validate-metric-keys(metrics-dict, version) = {
  let valid-metrics = get-valid-metrics(version)

  for (key, value) in metrics-dict {
    if key not in valid-metrics {
      let valid-list = valid-metrics.join(", ")
      panic("Invalid metric '" + key + "' for CVSS v" + version + ". Valid metrics: " + valid-list)
    }
  }
}

/// Validate that all metric values are valid for their metrics
///
/// - metrics-dict (dictionary): Dictionary of metric key-value pairs (should be normalised)
/// - version (string): CVSS version ("2.0", "3.0", "3.1", or "4.0")
/// -> none (panics on validation failure)
#let validate-metric-values(metrics-dict, version) = {
  for (key, value) in metrics-dict {
    let valid-values = get-valid-values(version, key)

    if valid-values.len() == 0 {
      // Metric key doesn't exist - should be caught by validate-metric-keys
      continue
    }

    if value not in valid-values {
      let valid-list = valid-values.join(", ")
      panic("Invalid value '" + value + "' for metric '" + key + "' in CVSS v" + version + ". Valid values: " + valid-list)
    }
  }
}

/// Validate that all required base metrics are present
///
/// - metrics-dict (dictionary): Dictionary of metric key-value pairs (should be normalised)
/// - version (string): CVSS version ("2.0", "3.0", "3.1", or "4.0")
/// -> none (panics on validation failure)
#let validate-required-base-metrics(metrics-dict, version) = {
  let required = get-required-base-metrics(version)
  let present-keys = metrics-dict.keys()

  for metric in required {
    if metric not in present-keys {
      let required-list = required.join(", ")
      panic("Missing required base metric '" + metric + "' for CVSS v" + version + ". Required: " + required-list)
    }
  }
}

/// Perform complete validation of a CVSS vector
///
/// - metrics-dict (dictionary): Dictionary of metric key-value pairs
/// - version (string): CVSS version ("2.0", "3.0", "3.1", or "4.0")
/// -> dictionary (normalised metrics)
#let validate(metrics-dict, version) = {
  // Normalise to uppercase
  let normalised = normalise-metrics(metrics-dict)

  // Validate in order: keys, values, required metrics
  validate-metric-keys(normalised, version)
  validate-metric-values(normalised, version)
  validate-required-base-metrics(normalised, version)

  // Return normalised dictionary if validation passed
  normalised
}
