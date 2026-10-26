use core::convert::Infallible;
use hmac::{Hmac, Mac};
use rand_core::{TryCryptoRng, TryRng, utils};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::{self, File},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    time::Instant,
};
use x_wing::{Decapsulate, Encapsulate, Kem, XWingKem};

type HmacSha256 = Hmac<Sha256>;

const ARCHITECTURES: [&str; 5] = [
    "A0_SHARED",
    "A1_LABEL_ONLY",
    "A2_GLOBAL_SPLIT_SHAM",
    "A3_ROLE_ROUTED",
    "A4_HEDGED",
];
const RECIPES: [&str; 3] = [
    "nominal",
    "origin_rng_state_reuse",
    "origin_rng_and_context_reuse",
];

struct BytesRng {
    bytes: Vec<u8>,
    position: usize,
}

impl BytesRng {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, position: 0 }
    }
}

impl TryRng for BytesRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        utils::next_word_via_fill(self)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        utils::next_word_via_fill(self)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        let end = self.position + dest.len();
        dest.copy_from_slice(&self.bytes[self.position..end]);
        self.position = end;
        Ok(())
    }
}

impl TryCryptoRng for BytesRng {}

#[derive(Serialize)]
struct Record {
    schema_version: &'static str,
    architecture: &'static str,
    recipe: &'static str,
    origin_component: &'static str,
    trial: usize,
    randomness_sha256: String,
    mlkem_ciphertext_sha256: String,
    x25519_ciphertext_sha256: String,
    hybrid_ciphertext_sha256: String,
    hybrid_shared_secret_sha256: String,
    honest_agreement: bool,
    derivation_elapsed_ns: u128,
    crypto_elapsed_ns: u128,
    total_elapsed_ns: u128,
}

#[derive(Default, Serialize)]
struct CellSummary {
    units: usize,
    agreement_failures: usize,
    mlkem_unique: usize,
    x25519_unique: usize,
    hybrid_ciphertext_unique: usize,
    hybrid_shared_secret_unique: usize,
    mlkem_repeats_after_first: usize,
    x25519_repeats_after_first: usize,
    hybrid_ciphertext_repeats_after_first: usize,
    hybrid_shared_secret_repeats_after_first: usize,
}

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part);
    }
    digest.finalize().into()
}

fn hash_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn hedge(key: &[u8; 32], raw: &[u8; 32], label: &[u8], context: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("32-byte HMAC key");
    mac.update(b"P01-HEDGE-V1");
    mac.update(label);
    mac.update(raw);
    mac.update(context);
    mac.finalize().into_bytes().into()
}

fn trial_context(trial: usize, reused: bool) -> [u8; 32] {
    if reused {
        hash(&[b"context-reset", &0_u64.to_le_bytes()])
    } else {
        hash(&[b"context", &(trial as u64).to_le_bytes()])
    }
}

fn derive_randomness(
    architecture: &'static str,
    recipe: &'static str,
    trial: usize,
) -> [u8; 64] {
    let event_active = recipe != "nominal";
    let context_reused = recipe == "origin_rng_and_context_reuse";
    let changing = (trial as u64).to_le_bytes();
    let frozen = 0_u64.to_le_bytes();
    let shared_index = if event_active { &frozen } else { &changing };
    let raw_shared = hash(&[b"raw-shared", shared_index]);
    let mut out = [0_u8; 64];

    match architecture {
        "A0_SHARED" => {
            out[..32].copy_from_slice(&hash(&[b"direct-mlkem", &raw_shared]));
            out[32..].copy_from_slice(&hash(&[b"direct-x25519", &raw_shared]));
        }
        "A1_LABEL_ONLY" => {
            out[..32].copy_from_slice(&hash(&[b"label-mlkem", &raw_shared]));
            out[32..].copy_from_slice(&hash(&[b"label-x25519", &raw_shared]));
        }
        "A2_GLOBAL_SPLIT_SHAM" => {
            // Intentional negative control: a nominally separate global source
            // is outside X-Wing's reached RNG interface, so both components
            // still consume the rolled-back caller-provided state.
            out[..32].copy_from_slice(&hash(&[b"sham-mlkem", &raw_shared]));
            out[32..].copy_from_slice(&hash(&[b"sham-x25519", &raw_shared]));
        }
        "A3_ROLE_ROUTED" => {
            let mlkem_index = if event_active { &frozen } else { &changing };
            let raw_mlkem = hash(&[b"raw-mlkem-state", mlkem_index]);
            let raw_x25519 = hash(&[b"raw-x25519-state", &changing]);
            out[..32].copy_from_slice(&raw_mlkem);
            out[32..].copy_from_slice(&raw_x25519);
        }
        "A4_HEDGED" => {
            let key_mlkem = hash(&[b"protected-secret-mlkem"]);
            let key_x25519 = hash(&[b"protected-secret-x25519"]);
            let context = trial_context(trial, context_reused);
            out[..32].copy_from_slice(&hedge(
                &key_mlkem,
                &raw_shared,
                b"ML-KEM-768",
                &context,
            ));
            out[32..].copy_from_slice(&hedge(
                &key_x25519,
                &raw_shared,
                b"X25519",
                &context,
            ));
        }
        _ => unreachable!("frozen architecture list"),
    }
    out
}

fn write_json(path: &Path, value: &impl Serialize) {
    let file = File::create(path).expect("create JSON output");
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, value).expect("serialize JSON output");
    writer.write_all(b"\n").expect("finish JSON output");
    writer.flush().expect("flush JSON output");
}

fn parse_args() -> (PathBuf, usize, Option<(String, String, usize, usize)>) {
    let args: Vec<String> = env::args().collect();
    let mut output = PathBuf::from("evidence");
    let mut trials = 32_usize;
    let mut unit_architecture: Option<String> = None;
    let mut unit_recipe: Option<String> = None;
    let mut unit_anchor = 0_usize;
    let mut unit_trial = 0_usize;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--output-dir" => {
                index += 1;
                output = PathBuf::from(&args[index]);
            }
            "--trials" => {
                index += 1;
                trials = args[index].parse().expect("integer --trials");
            }
            "--unit-architecture" => {
                index += 1;
                unit_architecture = Some(args[index].clone());
            }
            "--unit-recipe" => {
                index += 1;
                unit_recipe = Some(args[index].clone());
            }
            "--unit-anchor" => {
                index += 1;
                unit_anchor = args[index].parse().expect("integer --unit-anchor");
            }
            "--unit-trial" => {
                index += 1;
                unit_trial = args[index].parse().expect("integer --unit-trial");
            }
            unknown => panic!("unknown argument: {unknown}"),
        }
        index += 1;
    }
    let unit = if unit_architecture.is_some() || unit_recipe.is_some() || unit_trial != 0 {
        assert!(unit_architecture.is_some() && unit_recipe.is_some() && unit_trial > 0,
                "single-pair mode requires architecture, recipe and trial > 0");
        Some((unit_architecture.unwrap(), unit_recipe.unwrap(), unit_anchor, unit_trial))
    } else {
        assert!(trials >= 2, "at least two trials are required");
        None
    };
    (output, trials, unit)
}

fn main() {
    let (output_dir, trials, unit) = parse_args();
    let binary_sha256 = hash_hex(&fs::read("/proc/self/exe").expect("read running binary"));

    let recipient_seed = hash(&[b"P01-XWING-RECIPIENT-V1"]);
    let mut recipient_rng = BytesRng::new(recipient_seed.to_vec());
    let (decapsulation_key, encapsulation_key) =
        XWingKem::generate_keypair_from_rng(&mut recipient_rng);

    let run_record = |architecture: &'static str, recipe: &'static str, trial: usize| {
        let total_started = Instant::now();
        let derivation_started = Instant::now();
        let randomness = derive_randomness(architecture, recipe, trial);
        let derivation_elapsed_ns = derivation_started.elapsed().as_nanos();
        let mut rng = BytesRng::new(randomness.to_vec());
        let crypto_started = Instant::now();
        let (ciphertext, shared_secret) = encapsulation_key.encapsulate_with_rng(&mut rng);
        let received_secret = decapsulation_key.decapsulate(&ciphertext);
        let crypto_elapsed_ns = crypto_started.elapsed().as_nanos();
        let total_elapsed_ns = total_started.elapsed().as_nanos();
        let ciphertext_bytes: &[u8] = &ciphertext;
        assert_eq!(ciphertext_bytes.len(), 1120);
        Record {
            schema_version: "1.0",
            architecture,
            recipe,
            origin_component: "ML-KEM-768",
            trial,
            randomness_sha256: hash_hex(&randomness),
            mlkem_ciphertext_sha256: hash_hex(&ciphertext_bytes[..1088]),
            x25519_ciphertext_sha256: hash_hex(&ciphertext_bytes[1088..]),
            hybrid_ciphertext_sha256: hash_hex(ciphertext_bytes),
            hybrid_shared_secret_sha256: hash_hex(&shared_secret),
            honest_agreement: shared_secret == received_secret,
            derivation_elapsed_ns,
            crypto_elapsed_ns,
            total_elapsed_ns,
        }
    };

    if let Some((architecture_value, recipe_value, anchor_trial, comparison_trial)) = unit {
        let architecture = *ARCHITECTURES.iter().find(|item| **item == architecture_value)
            .expect("known --unit-architecture");
        let recipe = *RECIPES.iter().find(|item| **item == recipe_value)
            .expect("known --unit-recipe");
        let anchor = run_record(architecture, recipe, anchor_trial);
        let comparison = run_record(architecture, recipe, comparison_trial);
        let mlkem_freshness_preserved = anchor.mlkem_ciphertext_sha256 != comparison.mlkem_ciphertext_sha256;
        let x25519_freshness_preserved = anchor.x25519_ciphertext_sha256 != comparison.x25519_ciphertext_sha256;
        let hybrid_freshness_preserved = anchor.hybrid_ciphertext_sha256 != comparison.hybrid_ciphertext_sha256;
        let pair = serde_json::json!({
            "schema_version": "1.0",
            "implementation": "rustcrypto-x-wing",
            "source_commit": "19275cb6fd15ee64fc5ca93342c22e94dee65f38",
            "architecture": architecture,
            "recipe": recipe,
            "anchor_trial": anchor_trial,
            "comparison_trial": comparison_trial,
            "anchor": anchor,
            "comparison": comparison,
            "mlkem_freshness_preserved": mlkem_freshness_preserved,
            "x25519_freshness_preserved": x25519_freshness_preserved,
            "peer_freshness_preserved": x25519_freshness_preserved,
            "hybrid_freshness_preserved": hybrid_freshness_preserved,
        });
        serde_json::to_writer(std::io::stdout(), &pair).expect("serialize pair");
        println!();
        return;
    }

    fs::create_dir_all(&output_dir).expect("create output directory");
    fs::copy("/evidence/Cargo.lock", output_dir.join("Cargo.lock"))
        .expect("copy frozen Cargo.lock into evidence");

    let record_path = output_dir.join("records.jsonl");
    let record_file = File::create(&record_path).expect("create record file");
    let mut record_writer = BufWriter::new(record_file);
    let mut cells: BTreeMap<String, Vec<Record>> = BTreeMap::new();

    for architecture in ARCHITECTURES {
        for recipe in RECIPES {
            for trial in 0..trials {
                let record = run_record(architecture, recipe, trial);
                serde_json::to_writer(&mut record_writer, &record).expect("serialize record");
                record_writer.write_all(b"\n").expect("terminate record");
                record_writer.flush().expect("durable unit flush");
                record_writer.get_ref().sync_data().expect("durable unit fsync");
                cells
                    .entry(format!("{architecture}|{recipe}"))
                    .or_default()
                    .push(record);
            }
        }
    }
    record_writer.flush().expect("flush records");
    record_writer.get_ref().sync_all().expect("fsync records");

    let mut summaries: BTreeMap<String, CellSummary> = BTreeMap::new();
    for (cell, records) in &cells {
        let mlkem: BTreeSet<_> = records.iter().map(|r| &r.mlkem_ciphertext_sha256).collect();
        let x25519: BTreeSet<_> = records.iter().map(|r| &r.x25519_ciphertext_sha256).collect();
        let hybrid_ct: BTreeSet<_> = records.iter().map(|r| &r.hybrid_ciphertext_sha256).collect();
        let hybrid_ss: BTreeSet<_> = records
            .iter()
            .map(|r| &r.hybrid_shared_secret_sha256)
            .collect();
        summaries.insert(
            cell.clone(),
            CellSummary {
                units: records.len(),
                agreement_failures: records.iter().filter(|r| !r.honest_agreement).count(),
                mlkem_unique: mlkem.len(),
                x25519_unique: x25519.len(),
                hybrid_ciphertext_unique: hybrid_ct.len(),
                hybrid_shared_secret_unique: hybrid_ss.len(),
                mlkem_repeats_after_first: records.len() - mlkem.len(),
                x25519_repeats_after_first: records.len() - x25519.len(),
                hybrid_ciphertext_repeats_after_first: records.len() - hybrid_ct.len(),
                hybrid_shared_secret_repeats_after_first: records.len() - hybrid_ss.len(),
            },
        );
    }

    let summary = serde_json::json!({
        "schema_version": "1.0",
        "scientific_status": "REDESIGN_DEVELOPMENT_PILOT_NOT_CONFIRMATION",
        "source_commit": "19275cb6fd15ee64fc5ca93342c22e94dee65f38",
        "xwing_crate_version": "0.1.1",
        "binary_sha256": binary_sha256,
        "trials_per_cell": trials,
        "units": ARCHITECTURES.len() * RECIPES.len() * trials,
        "architectures": ARCHITECTURES,
        "recipes": RECIPES,
        "cells": summaries,
        "limitations": [
            "Software-level deterministic entropy intervention; not a physical fault prevalence model.",
            "Freshness and honest agreement are observed; unpredictability and IND-CCA security are not experimentally proved.",
            "A4 is an RFC-8937-style prior-art baseline with an explicit context-reset boundary, not a claimed new hedge."
        ]
    });
    write_json(&output_dir.join("summary.json"), &summary);

    let envelope = serde_json::json!({
        "schema_version": "1.0",
        "cargo_lock": {"path": "Cargo.lock", "sha256": hash_hex(&fs::read(output_dir.join("Cargo.lock")).expect("read Cargo.lock"))},
        "records": {"path": "records.jsonl", "sha256": hash_hex(&fs::read(&record_path).expect("read records"))},
        "summary": {"path": "summary.json", "sha256": hash_hex(&fs::read(output_dir.join("summary.json")).expect("read summary"))},
        "status": "PASS"
    });
    write_json(&output_dir.join("evidence-envelope.json"), &envelope);
}

#[cfg(test)]
mod tests {
    use super::derive_randomness;

    #[test]
    fn matched_reuse_has_frozen_architecture_semantics() {
        let a0_first = derive_randomness("A0_SHARED", "origin_rng_state_reuse", 0);
        let a0_second = derive_randomness("A0_SHARED", "origin_rng_state_reuse", 1);
        assert_eq!(a0_first, a0_second);

        let a2_first = derive_randomness("A2_GLOBAL_SPLIT_SHAM", "origin_rng_state_reuse", 0);
        let a2_second = derive_randomness("A2_GLOBAL_SPLIT_SHAM", "origin_rng_state_reuse", 1);
        assert_eq!(a2_first, a2_second);

        let a3_first = derive_randomness("A3_ROLE_ROUTED", "origin_rng_state_reuse", 0);
        let a3_second = derive_randomness("A3_ROLE_ROUTED", "origin_rng_state_reuse", 1);
        assert_eq!(&a3_first[..32], &a3_second[..32]);
        assert_ne!(&a3_first[32..], &a3_second[32..]);

        let a4_first = derive_randomness("A4_HEDGED", "origin_rng_state_reuse", 0);
        let a4_second = derive_randomness("A4_HEDGED", "origin_rng_state_reuse", 1);
        assert_ne!(a4_first, a4_second);

        let a4_reset_first =
            derive_randomness("A4_HEDGED", "origin_rng_and_context_reuse", 0);
        let a4_reset_second =
            derive_randomness("A4_HEDGED", "origin_rng_and_context_reuse", 1);
        assert_eq!(a4_reset_first, a4_reset_second);
    }
}
