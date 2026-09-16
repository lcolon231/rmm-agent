// SPDX-License-Identifier: AGPL-3.0-only
import { getRuntimeConfig } from "@/lib/runtime-config";
import { handleChat } from "@/lib/support-chat-route-core";

export const dynamic = "force-dynamic";
async function handle(request: Request, context: { params: Promise<{ parts: string[] }> }) {
  return handleChat(request, (await context.params).parts, getRuntimeConfig().apiBaseUrl);
}
export { handle as GET, handle as POST };
