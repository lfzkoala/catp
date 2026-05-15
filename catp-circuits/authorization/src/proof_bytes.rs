/// Opaque proof bytes. The concrete format is determined by the proving system.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Proof(pub Vec<u8>);
