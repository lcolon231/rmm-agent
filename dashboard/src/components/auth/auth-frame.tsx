// SPDX-License-Identifier: AGPL-3.0-only
import Image from "next/image";
import type { ReactNode } from "react";
export function AuthFrame({ children }: { children: ReactNode }) {
 return <main className="flex min-h-dvh flex-col items-center justify-start bg-(--fog) px-4 py-10 text-sm text-(--slate)">
  <div className="my-auto grid w-full max-w-[420px] gap-6">
   <div className="flex items-center justify-center gap-3"><Image src="/brand/nodelink-logo.jpg" alt="" width={36} height={36} className="rounded-lg" /><strong className="text-xl text-(--ink)">NodeLink</strong></div>
   <section className="grid gap-4 rounded-[10px] border border-(--line) bg-(--paper) p-8 shadow-sm [&_h1]:text-2xl [&_h1]:font-semibold [&_h1]:leading-[1.3] [&_h1]:text-(--ink) [&_form]:grid [&_form]:gap-3 [&_label]:text-[13px] [&_label]:font-semibold [&_input]:min-h-11 [&_input]:w-full [&_input]:rounded-lg [&_input]:border [&_input]:border-(--line-strong) [&_input]:px-3 [&_small]:text-xs [&_small]:text-(--muted) [&_a]:text-(--primary-strong)">{children}</section>
   <p className="text-center text-xs text-(--muted)">Use an account issued by your NodeLink administrator.</p>
  </div>
 </main>;
}
