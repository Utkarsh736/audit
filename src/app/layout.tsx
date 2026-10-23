import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Toaster } from "@/components/ui/toaster";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Auditor — Security Audit Dashboard",
  description:
    "Agentic security auditor: deterministic scanners (secrets, prompt injection, auth, PII, XSS) with OWASP/CWE remediation guidance, CLI + web dashboard.",
  keywords: ["security", "audit", "OWASP", "LLM security", "SAST", "vulnerability scanner"],
  authors: [{ name: "Auditor" }],
  openGraph: {
    title: "Auditor — Security Audit Dashboard",
    description: "Scan projects for vulnerabilities and get actionable remediation guidance.",
    siteName: "Auditor",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-background text-foreground`}
      >
        {children}
        <Toaster />
      </body>
    </html>
  );
}
