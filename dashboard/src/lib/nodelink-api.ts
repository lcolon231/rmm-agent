// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import {
  type NodelinkRequestOptions,
  requestNodelinkApi,
  requestNodelinkApiRaw,
} from "@/lib/nodelink-api-core";
import { getRuntimeConfig } from "@/lib/runtime-config";

export { NodelinkApiError, extractNodelinkErrorCode } from "@/lib/nodelink-api-core";

export async function nodelinkApiRequest<T>(
  path: string,
  options: NodelinkRequestOptions,
): Promise<T> {
  return requestNodelinkApi(path, options, {
    fetchImpl: fetch,
    runtimeConfig: getRuntimeConfig(),
  });
}

/** Raw-response variant for streaming a non-JSON payload (issue #9). */
export async function nodelinkApiRequestRaw(
  path: string,
  options: NodelinkRequestOptions,
): Promise<Response> {
  return requestNodelinkApiRaw(path, options, {
    fetchImpl: fetch,
    runtimeConfig: getRuntimeConfig(),
  });
}
