// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { mock, test } from "node:test";
import { fireEvent, render, screen } from "@testing-library/react";
mock.module("next/image", {
 // eslint-disable-next-line @next/next/no-img-element -- test stand-in
 defaultExport: ({ alt, src }: { alt: string; src: string }) => <img alt={alt} src={src} />,
});
const { MfaChallengeForm } = await import("@/components/mfa-challenge-form");
const { BreakGlassActivateForm } = await import("@/components/break-glass-activate-form");
test("an email-only MFA account keeps its usable path and does not claim delivery", async (t) => {
 t.mock.method(globalThis,"fetch",async () => Response.json({destination:"a***@example.test"}));
 render(<MfaChallengeForm enrollmentRequired={false} methods={["email_code"]} />);
 assert.equal(screen.queryByRole("button",{name:"Use security key"}),null);
 fireEvent.click(screen.getByRole("button",{name:"Email me a code"}));
 assert.ok(await screen.findByText(/A code was requested/));
 assert.ok(screen.getByLabelText("Emailed code"));
});
test("mandatory MFA enrollment does not expose fallback methods", () => {
 render(<MfaChallengeForm enrollmentRequired methods={["enrollment","email_code","recovery_code"]} />);
 assert.ok(screen.getByRole("heading",{name:"Register a security key"}));
 assert.equal(screen.queryByRole("button",{name:/Email me/}),null);
 assert.equal(screen.queryByLabelText("Recovery code"),null);
});
test("emergency credentials and reason stay in the request body and refusal stays visible",async(t)=>{
 const fetchMock=t.mock.method(globalThis,"fetch",async()=>Response.json({error:"Emergency access disabled"},{status:403}));
 render(<BreakGlassActivateForm />);
 fireEvent.change(screen.getByLabelText("Emergency credential"),{target:{value:"nlbg_secret"}});
 fireEvent.change(screen.getByLabelText("Why are you using it?"),{target:{value:"All keys lost"}});
 fireEvent.submit(screen.getByRole("button",{name:"Start emergency session"}).closest("form")!);
 assert.ok(await screen.findByRole("alert"));
 const [url,init]=fetchMock.mock.calls[0].arguments as unknown as [string,RequestInit];
 assert.equal(url,"/api/auth/break-glass/activate"); assert.deepEqual(JSON.parse(init.body as string),{credential:"nlbg_secret",reason:"All keys lost"});
 assert.equal(screen.getByRole("link",{name:"Back to normal sign in"}).getAttribute("href"),"/login");
});
