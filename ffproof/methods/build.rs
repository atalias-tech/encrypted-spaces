// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::HashMap;
use std::path::Path;

use risc0_build::{
    embed_methods, embed_methods_with_options, DockerOptionsBuilder, GuestOptionsBuilder,
};

// The guest package whose bins (extend_ff, hash_test) become EXTEND_FF_* and
// HASH_TEST_* constants. Matches `name` in guest/Cargo.toml.
const GUEST_PKG: &str = "encrypted-spaces-ffproof";

fn main() {
    // Reproducible, HOST-INDEPENDENT ImageID when RISC0_USE_DOCKER is set.
    //
    // A plain native `embed_methods()` bakes environment-sensitive bytes (the
    // absolute build path) into the guest ELF, so its EXTEND_FF_ID differs per
    // machine. risc0's Docker build compiles the guest inside the pinned
    // `risczero/risc0-guest-builder` container at a FIXED path, so the resulting
    // ID is identical on any host — native CPU, native CUDA, or full Docker.
    //
    // The canonical ID committed at config/ff_image_id.txt is produced this way.
    // The real-proofs SERVER must build with RISC0_USE_DOCKER=1 so the proofs it
    // emits carry that canonical ID and existing clients verify them. The
    // verify-only clients never build the guest at all (they read the pinned
    // file), so this only affects prover/server builds and ID regeneration.
    //
    // Default (unset) = fast native build for local dev/tests. Its ID is
    // machine-local and must NOT be deployed as a server.
    // (scripts/realproofs-server.sh sets RISC0_USE_DOCKER=1 and verifies the
    // built ID against config/ff_image_id.txt before serving.)
    println!("cargo:rerun-if-env-changed=RISC0_USE_DOCKER");

    if std::env::var_os("RISC0_USE_DOCKER").is_some() {
        // root_dir = the encrypted-spaces submodule root (two levels up from this
        // methods crate). It must contain the guest crate (ffproof/methods/guest),
        // every path-dependency it pulls (ffproof/changelog_core ->
        // ffproof/tracer/shared), AND the submodule's workspace `Cargo.toml` —
        // changelog_core inherits `edition`/`version` via `*.workspace = true`,
        // so the workspace root manifest must be in the Docker build context.
        // This fixed root also fixes the guest's in-container build path, which is
        // what makes the resulting EXTEND_FF_ID host-independent and reproducible.
        let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
        let root_dir = Path::new(&manifest).join("..").join(".."); // vendor/encrypted-spaces

        let docker = DockerOptionsBuilder::default()
            .root_dir(root_dir)
            .build()
            .expect("docker options");
        let opts = GuestOptionsBuilder::default()
            .use_docker(docker)
            .build()
            .expect("guest options");

        embed_methods_with_options(HashMap::from([(GUEST_PKG, opts)]));
    } else {
        embed_methods();
    }
}
