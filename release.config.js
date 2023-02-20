module.exports = {
  branches: ["master"],
  plugins: [
    "@semantic-release/commit-analyzer",
    "@semantic-release/release-notes-generator",
    "@semantic-release/changelog",
    "@semantic-release/npm",
    [
      "@semantic-release/git",
      {
        assets: ["package.json", "CHANGELOG.md"],
        message: "chore(release): ${nextRelease.version} [skip ci]",
      },
    ],
    [
      "@semantic-release/github",
      {
        assets: [
          "dist/wiregasm.js",
          "dist/wiregasm.wasm",
          "dist/wiregasm.data",
        ],
      },
    ],
  ],
};
