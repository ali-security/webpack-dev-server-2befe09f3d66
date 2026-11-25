"use strict";

module.exports = {
  testURL: "http://localhost/",
  collectCoverage: false,
  coveragePathIgnorePatterns: [
    "/node_modules/",
    "<rootDir>/test/",
    "<rootDir>/client/",
  ],
  testPathIgnorePatterns: [
    "<rootDir>/bin/this/process-arguments.js",
    // puppeteer 13 predates mac-arm64 support: its Chromium hangs the jest
    // worker on Apple Silicon runners, so e2e suites run on Linux/Windows only.
    ...(process.platform === "darwin" ? ["<rootDir>/test/e2e/"] : []),
  ],
  snapshotResolver: "<rootDir>/test/helpers/snapshotResolver.js",
  setupFilesAfterEnv: ["<rootDir>/setupTest.js"],
  globalSetup: "<rootDir>/globalSetupTest.js",
};
