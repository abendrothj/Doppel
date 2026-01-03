// Parameter Analysis & Manipulation Module
//
// This module provides comprehensive parameter handling for BOLA/IDOR detection:
//
// - substitution: Runtime JSON value mutation during attacks
// - classifier: Static semantic analysis and risk scoring
// - scanner: Endpoint-level integration and filtering
//
// Architecture:
//   substitution.rs (independent, runtime)
//       ↓ (used by main.rs)
//
//   classifier.rs (leaf, static analysis)
//       ↑
//   scanner.rs (uses classifier, integrates with endpoints)
//       ↑
//   main.rs (uses scanner for planning)

pub mod classifier;
pub mod scanner;
pub mod substitution;

// Re-export commonly used items for convenience
pub use classifier::*;
pub use scanner::*;
pub use substitution::*;
