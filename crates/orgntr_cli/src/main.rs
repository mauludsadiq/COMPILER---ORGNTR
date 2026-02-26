use orgntr_ocir::ir::{OModule, OInst};
use orgntr_ocir::verify;
use orgntr_target_x86_64::{emit_object_x86_64_sysv_stage1, TrustRecord};

fn main() {
    // Stage I demo: 40 + 2
    let m = OModule {
        entry_name: "fard_main".to_string(),
        instructions: vec![
            OInst::ImmI64 { dst: 1, val: 40 },
            OInst::ImmI64 { dst: 2, val: 2 },
            OInst::AddI64 { dst: 3, lhs: 1, rhs: 2 },
            OInst::RetI64 { src: 3 },
        ],
    };

    verify(&m).expect("ocir verify");

    let ocir_hash = m.compute_hash_hex();

    let trust = TrustRecord {
        fard_version: "0.5.0".to_string(),
        asc7_graph_hash: "sha256:dev".to_string(),
        ocir_hash,
        h_sem_bits: 0.0,
        delta: 0,
        target: "x86_64-sysv".to_string(),
    };

    let obj_bytes = emit_object_x86_64_sysv_stage1(&m, &trust);

    std::fs::write("out.o", obj_bytes).expect("write out.o");
    eprintln!("wrote out.o");
}
