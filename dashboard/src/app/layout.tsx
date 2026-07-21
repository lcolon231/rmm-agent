import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "NodeLink Operations",
  description: "Risk-first endpoint operations and verifiable audit evidence.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
