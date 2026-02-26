use serde::Serialize;

#[derive(Serialize, Debug, Clone)]
pub struct TrustRecord {
    pub fard_version: String,       // "0.5.0"
    pub asc7_graph_hash: String,    // "sha256:..."
    pub ocir_hash: String,          // hex sha256
    pub h_sem_bits: f64,
    pub delta: u8,
    pub target: String,             // "x86_64-sysv"
}

impl TrustRecord {
    pub fn to_json_bytes(&self) -> Vec<u8> {
        // Stage I: stable enough; replace with canonical JSON later.
        serde_json::to_string(self).expect("trust json").into_bytes()
    }
}
