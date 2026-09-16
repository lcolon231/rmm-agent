// SPDX-License-Identifier: AGPL-3.0-only
import type { Metadata } from "next";
import { SupportChatPanel } from "@/components/support-chat-panel";

export const metadata: Metadata = { title: "NodeLink Support", robots: { index: false, follow: false }, referrer: "no-referrer" };
export default function ChatPage() { return <SupportChatPanel />; }
