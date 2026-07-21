// SPDX-License-Identifier: AGPL-3.0-only

import { getRuntimeConfig } from "../src/lib/runtime-config.ts";

const runtimeConfig = getRuntimeConfig();
console.log(`NodeLink API configuration is valid (${runtimeConfig.apiBaseUrl}).`);
