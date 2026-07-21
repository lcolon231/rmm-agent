// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import {
  type NodelinkRequestOptions,
  NodelinkApiError,
  requestNodelinkApi,
} from "@/lib/nodelink-api-core";
import { getRuntimeConfig } from "@/lib/runtime-config";

export { NodelinkApiError };

export async function nodelinkApiRequest<T>(
  path: string,
  options: NodelinkRequestOptions,
): Promise<T> {
  return requestNodelinkApi(path, options, {
    fetchImpl: fetch,
    runtimeConfig: getRuntimeConfig(),
  });
}
