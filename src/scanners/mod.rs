pub mod deps;
pub mod obfuscation;
pub mod sast;
pub mod secrets;
pub mod supply_chain;

use crate::scanner::Scanner;
use std::sync::Arc;

/// L'obfuscation passe en premier : c'est la menace prioritaire, et le rapport
/// suit cet ordre.
pub fn all_scanners() -> Vec<Arc<dyn Scanner>> {
    vec![
        Arc::new(obfuscation::ObfuscationScanner),
        Arc::new(secrets::SecretsScanner),
        Arc::new(deps::DepsScanner),
        Arc::new(supply_chain::SupplyChainScanner),
        Arc::new(sast::SastScanner),
    ]
}

pub fn secrets_scanners() -> Vec<Arc<dyn Scanner>> {
    vec![Arc::new(secrets::SecretsScanner)]
}

pub fn deps_scanners() -> Vec<Arc<dyn Scanner>> {
    vec![Arc::new(deps::DepsScanner)]
}

pub fn sast_scanners() -> Vec<Arc<dyn Scanner>> {
    vec![Arc::new(sast::SastScanner)]
}

pub fn supply_chain_scanners() -> Vec<Arc<dyn Scanner>> {
    vec![Arc::new(supply_chain::SupplyChainScanner)]
}

pub fn obfuscation_scanners() -> Vec<Arc<dyn Scanner>> {
    vec![Arc::new(obfuscation::ObfuscationScanner)]
}
