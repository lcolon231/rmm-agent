"use client";

export default function EnrollmentError({ reset }: { error: Error; reset: () => void }) {
  return <section className="enrollment-empty" role="alert"><h2>Enrollment data is unavailable</h2><p>The management API did not return a usable response. No action was taken.</p><button onClick={reset}>Try again</button></section>;
}
