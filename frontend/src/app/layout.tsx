import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "NestJS Scanner — Code Review Tool",
  description: "Static analysis tool for NestJS projects. Detects security vulnerabilities, code quality issues, and pattern inconsistencies.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
