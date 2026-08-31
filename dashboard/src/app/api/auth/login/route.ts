// SPDX-License-Identifier: AGPL-3.0-only

import { NextRequest, NextResponse } from "next/server";

import {
  isSameOrigin,
  loginErrorMessage,
  type LoginErrorCode,
  readLoginSubmission,
  requestOrigin,
  sessionCookieName,
  sessionCookieOptions,
  validateLoginCredentials,
} from "@/lib/dashboard-auth-core";
import { applyMfaResult } from "@/lib/mfa-route";
import { loginOutcome } from "@/lib/mfa-route-core";
import { readLoginChallenge } from "@/lib/mfa-core";
import {
  NodelinkAuthenticationError,
  NodelinkSecondFactorRequired,
  authenticateOperator,
} from "@/lib/nodelink-auth";

export const dynamic = "force-dynamic";

function loginErrorResponse(
  responseOrigin: string,
  submissionKind: "form" | "json",
  errorCode: LoginErrorCode,
  status: number,
) {
  if (submissionKind === "form") {
    const loginUrl = new URL("/login", responseOrigin);
    loginUrl.searchParams.set("error", errorCode);
    return NextResponse.redirect(loginUrl, 303);
  }

  return NextResponse.json(
    { error: loginErrorMessage(errorCode) ?? "Sign-in is unavailable. Try again later." },
    { status },
  );
}

export async function POST(request: NextRequest) {
  const submission = await readLoginSubmission(request);
  const submissionKind = submission?.kind ?? "json";
  const responseOrigin = requestOrigin(request.url, request.headers.get("host"));

  if (!isSameOrigin(request.headers.get("origin"), responseOrigin)) {
    return loginErrorResponse(responseOrigin, submissionKind, "request-rejected", 403);
  }

  if (!submission) {
    return loginErrorResponse(responseOrigin, submissionKind, "invalid-request", 400);
  }

  const credentials = validateLoginCredentials(submission.body);
  if (!credentials) {
    return loginErrorResponse(responseOrigin, submissionKind, "invalid-request", 400);
  }

  try {
    const { operator, sessionToken } = await authenticateOperator(credentials);
    const response = submissionKind === "form"
      ? NextResponse.redirect(new URL("/", responseOrigin), 303)
      : NextResponse.json({ operator });
    response.cookies.set(sessionCookieName(), sessionToken, sessionCookieOptions());
    return response;
  } catch (error) {
    if (error instanceof NodelinkSecondFactorRequired) {
      // The password was correct but a second factor is owed. Stash the
      // restricted token in its own cookie and send the caller to the challenge
      // — never to "/", which would suggest a session that does not exist.
      const outcome = loginOutcome(error.body);
      const challenge = readLoginChallenge(error.body);
      if (outcome === null || challenge === null) {
        return loginErrorResponse(responseOrigin, submissionKind, "unavailable", 503);
      }
      if (submissionKind === "form") {
        const challengeUrl = new URL("/login/mfa", responseOrigin);
        if (challenge.methods.length > 0) {
          challengeUrl.searchParams.set("methods", challenge.methods.join(","));
        }
        if (challenge.enrollmentRequired) {
          challengeUrl.searchParams.set("enroll", "1");
        }
        const redirect = NextResponse.redirect(challengeUrl, 303);
        for (const cookie of outcome.cookies) {
          redirect.cookies.set(cookie.name, cookie.value, cookie.options);
        }
        return redirect;
      }
      return applyMfaResult(outcome);
    }

    if (error instanceof NodelinkAuthenticationError) {
      const status = error.status === 429 ? 429 : error.status === 401 ? 401 : 503;
      const errorCode = status === 401
        ? "invalid-credentials"
        : status === 429
          ? "rate-limited"
          : "unavailable";
      return loginErrorResponse(responseOrigin, submissionKind, errorCode, status);
    }

    return loginErrorResponse(responseOrigin, submissionKind, "unavailable", 503);
  }
}
