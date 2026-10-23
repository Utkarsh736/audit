import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Standalone output is useful for Docker / minimal deploys; keep it optional-friendly
  output: "standalone",
  reactStrictMode: true,
};

export default nextConfig;
