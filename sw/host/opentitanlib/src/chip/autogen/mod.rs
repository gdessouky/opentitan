// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// The "english breakfast" variant of the chip doesn't have the same
// set of IO and pinmux constants as the "earlgrey" chip.
#[cfg(not(feature = "english_breakfast"))]
pub mod earlgrey;
