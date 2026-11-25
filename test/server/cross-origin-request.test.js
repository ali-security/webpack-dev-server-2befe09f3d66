"use strict";

const path = require("path");
const url = require("url");
const request = require("supertest");
const webpack = require("webpack");
const WebSocket = require("ws");
const Server = require("../../lib/Server");
const config = require("../fixtures/client-config/webpack.config");
const port = require("../ports-map")["cross-origin-request-server"];

const staticDirectory = path.resolve(
  __dirname,
  "../fixtures/client-config/static"
);

describe("cross-origin request check", () => {
  let server;

  async function startServer(options) {
    const compiler = webpack(config);

    server = new Server(
      {
        static: {
          directory: staticDirectory,
          watch: false,
        },
        port,
        ...options,
      },
      compiler
    );

    await server.start();
  }

  afterEach(async () => {
    await server.stop();
  });

  describe("with the default 'allowedHosts' value", () => {
    it("should return 403 for cross-site no-cors requests to the bundle", async () => {
      await startServer({});

      const response = await request(server.app)
        .get("/main.js")
        .set("Host", `localhost:${port}`)
        .set("Sec-Fetch-Mode", "no-cors")
        .set("Sec-Fetch-Site", "cross-site");

      expect(response.status).toEqual(403);
      expect(response.text).toEqual("Cross-Origin request blocked");
    });

    it("should return 403 for cross-site no-cors requests to static files", async () => {
      await startServer({});

      const response = await request(server.app)
        .get("/foo.txt")
        .set("Host", `localhost:${port}`)
        .set("Sec-Fetch-Mode", "no-cors")
        .set("Sec-Fetch-Site", "cross-site");

      expect(response.status).toEqual(403);
      expect(response.text).toEqual("Cross-Origin request blocked");
    });

    it("should return 403 for cross-site no-cors requests with an IP address in the 'host' header", async () => {
      await startServer({});

      const response = await request(server.app)
        .get("/main.js")
        .set("Host", `127.0.0.1:${port}`)
        .set("Sec-Fetch-Mode", "no-cors")
        .set("Sec-Fetch-Site", "cross-site");

      expect(response.status).toEqual(403);
      expect(response.text).toEqual("Cross-Origin request blocked");
    });

    it("should return 200 for requests with an IP address in the 'host' header without 'sec-fetch-*' headers", async () => {
      await startServer({});

      const response = await request(server.app)
        .get("/main.js")
        .set("Host", `127.0.0.1:${port}`);

      expect(response.status).toEqual(200);
      expect(response.text).toContain("Hey.");
    });

    it("should return 200 for requests without 'sec-fetch-*' headers", async () => {
      await startServer({});

      const response = await request(server.app)
        .get("/main.js")
        .set("Host", `localhost:${port}`);

      expect(response.status).toEqual(200);
      expect(response.text).toContain("Hey.");
    });

    const allowedCombinations = [
      ["no-cors", "same-origin"],
      ["no-cors", "same-site"],
      ["no-cors", "none"],
      ["cors", "cross-site"],
      ["navigate", "cross-site"],
    ];

    for (const [mode, site] of allowedCombinations) {
      it(`should return 200 for "${mode}" mode and "${site}" site requests`, async () => {
        await startServer({});

        const response = await request(server.app)
          .get("/main.js")
          .set("Host", `localhost:${port}`)
          .set("Sec-Fetch-Mode", mode)
          .set("Sec-Fetch-Site", site);

        expect(response.status).toEqual(200);
        expect(response.text).toContain("Hey.");
      });
    }
  });

  describe("with the 'allowedHosts' option", () => {
    it("should return 200 for cross-site no-cors requests with the 'all' value", async () => {
      await startServer({ allowedHosts: "all" });

      const response = await request(server.app)
        .get("/main.js")
        .set("Host", `localhost:${port}`)
        .set("Sec-Fetch-Mode", "no-cors")
        .set("Sec-Fetch-Site", "cross-site");

      expect(response.status).toEqual(200);
      expect(response.text).toContain("Hey.");
    });

    it("should return 200 for cross-site no-cors requests with the 'localhost' value", async () => {
      await startServer({ allowedHosts: ["localhost"] });

      const response = await request(server.app)
        .get("/main.js")
        .set("Host", `localhost:${port}`)
        .set("Sec-Fetch-Mode", "no-cors")
        .set("Sec-Fetch-Site", "cross-site");

      expect(response.status).toEqual(200);
      expect(response.text).toContain("Hey.");
    });

    it("should return 200 for cross-site no-cors requests with the '.localhost' value", async () => {
      await startServer({ allowedHosts: [".localhost"] });

      const response = await request(server.app)
        .get("/main.js")
        .set("Host", `localhost:${port}`)
        .set("Sec-Fetch-Mode", "no-cors")
        .set("Sec-Fetch-Site", "cross-site");

      expect(response.status).toEqual(200);
      expect(response.text).toContain("Hey.");
    });

    it("should return 403 for cross-site no-cors requests when the 'host' header is not allowed", async () => {
      await startServer({ allowedHosts: ["my-test-host"] });

      const response = await request(server.app)
        .get("/main.js")
        .set("Host", `localhost:${port}`)
        .set("Sec-Fetch-Mode", "no-cors")
        .set("Sec-Fetch-Site", "cross-site");

      expect(response.status).toEqual(403);
      expect(response.text).toEqual("Cross-Origin request blocked");
    });
  });

  // @see https://github.com/webpack/webpack-dev-server/security/advisories/GHSA-79cf-xcqc-c78w
  describe("the 'Cross-Origin-Resource-Policy' header", () => {
    it("should be 'same-origin' for requests to the bundle without 'sec-fetch-*' headers", async () => {
      await startServer({});

      const response = await request(server.app)
        .get("/main.js")
        .set("Host", `localhost:${port}`);

      expect(response.status).toEqual(200);
      expect(response.headers["cross-origin-resource-policy"]).toEqual(
        "same-origin"
      );
    });

    it("should be 'same-origin' for requests to static files without 'sec-fetch-*' headers", async () => {
      await startServer({});

      const response = await request(server.app)
        .get("/foo.txt")
        .set("Host", `localhost:${port}`);

      expect(response.status).toEqual(200);
      expect(response.headers["cross-origin-resource-policy"]).toEqual(
        "same-origin"
      );
    });

    it("should be 'same-origin' for requests with an IP address in the 'host' header without 'sec-fetch-*' headers", async () => {
      await startServer({});

      const response = await request(server.app)
        .get("/main.js")
        .set("Host", `127.0.0.1:${port}`);

      expect(response.status).toEqual(200);
      expect(response.headers["cross-origin-resource-policy"]).toEqual(
        "same-origin"
      );
    });

    it("should be 'same-origin' when the 'host' header is not allowed", async () => {
      await startServer({ allowedHosts: ["my-test-host"] });

      const response = await request(server.app)
        .get("/main.js")
        .set("Host", `localhost:${port}`);

      expect(response.status).toEqual(200);
      expect(response.headers["cross-origin-resource-policy"]).toEqual(
        "same-origin"
      );
    });

    it("should not be set with the 'all' value of the 'allowedHosts' option", async () => {
      await startServer({ allowedHosts: "all" });

      const response = await request(server.app)
        .get("/main.js")
        .set("Host", `localhost:${port}`);

      expect(response.status).toEqual(200);
      expect(response.headers["cross-origin-resource-policy"]).toBeUndefined();
    });

    it("should not be set when the 'host' header is in the 'allowedHosts' option", async () => {
      await startServer({ allowedHosts: ["localhost"] });

      const response = await request(server.app)
        .get("/main.js")
        .set("Host", `localhost:${port}`);

      expect(response.status).toEqual(200);
      expect(response.headers["cross-origin-resource-policy"]).toBeUndefined();
    });

    it("should not be set with a wildcard 'Access-Control-Allow-Origin' header in the 'headers' object", async () => {
      await startServer({
        headers: { "Access-Control-Allow-Origin": "*" },
      });

      const response = await request(server.app)
        .get("/main.js")
        .set("Host", `localhost:${port}`);

      expect(response.status).toEqual(200);
      expect(response.headers["access-control-allow-origin"]).toEqual("*");
      expect(response.headers["cross-origin-resource-policy"]).toBeUndefined();
    });

    it("should not be set with a lowercase wildcard 'access-control-allow-origin' header in the 'headers' object", async () => {
      await startServer({
        headers: { "access-control-allow-origin": " * " },
      });

      const response = await request(server.app)
        .get("/main.js")
        .set("Host", `localhost:${port}`);

      expect(response.status).toEqual(200);
      expect(response.headers["cross-origin-resource-policy"]).toBeUndefined();
    });

    it("should not be set with a wildcard 'Access-Control-Allow-Origin' header in the 'headers' array", async () => {
      await startServer({
        headers: [{ key: "Access-Control-Allow-Origin", value: "*" }],
      });

      const response = await request(server.app)
        .get("/main.js")
        .set("Host", `localhost:${port}`);

      expect(response.status).toEqual(200);
      expect(response.headers["access-control-allow-origin"]).toEqual("*");
      expect(response.headers["cross-origin-resource-policy"]).toBeUndefined();
    });

    it("should be 'same-origin' with a specific origin 'Access-Control-Allow-Origin' header in the 'headers' object", async () => {
      await startServer({
        headers: { "Access-Control-Allow-Origin": "http://foo.example.com" },
      });

      const response = await request(server.app)
        .get("/main.js")
        .set("Host", `localhost:${port}`);

      expect(response.status).toEqual(200);
      expect(response.headers["cross-origin-resource-policy"]).toEqual(
        "same-origin"
      );
    });

    it("should be 'same-origin' with a specific origin 'Access-Control-Allow-Origin' header in the 'headers' array", async () => {
      await startServer({
        headers: [
          {
            key: "Access-Control-Allow-Origin",
            value: "http://foo.example.com",
          },
        ],
      });

      const response = await request(server.app)
        .get("/main.js")
        .set("Host", `localhost:${port}`);

      expect(response.status).toEqual(200);
      expect(response.headers["cross-origin-resource-policy"]).toEqual(
        "same-origin"
      );
    });

    it("should be 'same-origin' when the 'headers' option is a function", async () => {
      await startServer({
        headers: () => {
          return { "Access-Control-Allow-Origin": "*" };
        },
      });

      const response = await request(server.app)
        .get("/main.js")
        .set("Host", `localhost:${port}`);

      expect(response.status).toEqual(200);
      expect(response.headers["cross-origin-resource-policy"]).toEqual(
        "same-origin"
      );
    });
  });

  describe("the '/webpack-dev-server/invalidate' route", () => {
    const blockedCombinations = [
      ["cors", "cross-site"],
      ["no-cors", "cross-site"],
      ["navigate", "cross-site"],
      ["cors", "same-site"],
      ["no-cors", "same-site"],
    ];

    for (const [mode, site] of blockedCombinations) {
      it(`should return 403 for "${mode}" mode and "${site}" site requests`, async () => {
        await startServer({});

        const invalidateSpy = jest.spyOn(server, "invalidate");

        const response = await request(server.app)
          .get("/webpack-dev-server/invalidate")
          .set("Host", `localhost:${port}`)
          .set("Sec-Fetch-Mode", mode)
          .set("Sec-Fetch-Site", site);

        expect(response.status).toEqual(403);
        expect(response.text).toEqual("Cross-Origin request blocked");
        expect(invalidateSpy).not.toHaveBeenCalled();
      });
    }

    it("should return 403 for requests with a cross-origin 'origin' header without 'sec-fetch-*' headers", async () => {
      await startServer({});

      const invalidateSpy = jest.spyOn(server, "invalidate");

      const response = await request(server.app)
        .get("/webpack-dev-server/invalidate")
        .set("Host", `localhost:${port}`)
        .set("Origin", "http://evil.example");

      expect(response.status).toEqual(403);
      expect(response.text).toEqual("Cross-Origin request blocked");
      expect(invalidateSpy).not.toHaveBeenCalled();
    });

    const allowedCombinations = [
      ["cors", "same-origin"],
      ["navigate", "none"],
    ];

    for (const [mode, site] of allowedCombinations) {
      it(`should return 200 for "${mode}" mode and "${site}" site requests`, async () => {
        await startServer({});

        const invalidateSpy = jest.spyOn(server, "invalidate");

        const response = await request(server.app)
          .get("/webpack-dev-server/invalidate")
          .set("Host", `localhost:${port}`)
          .set("Sec-Fetch-Mode", mode)
          .set("Sec-Fetch-Site", site);

        expect(response.status).toEqual(200);
        expect(invalidateSpy).toHaveBeenCalledTimes(1);
      });
    }

    it("should return 200 for requests with a same-origin 'origin' header without 'sec-fetch-*' headers", async () => {
      await startServer({});

      const invalidateSpy = jest.spyOn(server, "invalidate");

      const response = await request(server.app)
        .get("/webpack-dev-server/invalidate")
        .set("Host", `localhost:${port}`)
        .set("Origin", `http://localhost:${port}`);

      expect(response.status).toEqual(200);
      expect(invalidateSpy).toHaveBeenCalledTimes(1);
    });

    it("should return 200 for requests without 'sec-fetch-*' and 'origin' headers", async () => {
      await startServer({});

      const invalidateSpy = jest.spyOn(server, "invalidate");

      const response = await request(server.app)
        .get("/webpack-dev-server/invalidate")
        .set("Host", `localhost:${port}`);

      expect(response.status).toEqual(200);
      expect(invalidateSpy).toHaveBeenCalledTimes(1);
    });
  });

  describe("malformed 'host' and 'origin' headers", () => {
    const malformedHost = "[::1";
    const malformedOrigin = "http://[::1/";

    let parseSpy;

    function throwOnMalformedHeaders() {
      const originalParse = url.parse;

      parseSpy = jest
        .spyOn(url, "parse")
        .mockImplementation((input, ...args) => {
          if (input === `//${malformedHost}` || input === malformedOrigin) {
            throw new TypeError("Invalid URL");
          }

          return originalParse(input, ...args);
        });
    }

    function connectWebSocket(headers) {
      return new Promise((resolve) => {
        const messages = [];
        const ws = new WebSocket(`ws://127.0.0.1:${port}/ws`, { headers });

        ws.on("message", (data) => {
          messages.push(JSON.parse(data));
        });
        ws.on("close", () => resolve(messages));
        ws.on("error", () => resolve(messages));
      });
    }

    afterEach(() => {
      if (parseSpy) {
        parseSpy.mockRestore();
        parseSpy = null;
      }
    });

    it("should return false from 'checkHeader' when the 'host' header cannot be parsed", async () => {
      await startServer({});

      throwOnMalformedHeaders();

      expect(server.checkHeader({ host: malformedHost }, "host", true)).toBe(
        false
      );
      expect(parseSpy).toHaveBeenCalledWith(`//${malformedHost}`, false, true);
    });

    it("should return false from 'checkHeader' when the 'origin' header cannot be parsed", async () => {
      await startServer({});

      throwOnMalformedHeaders();

      expect(
        server.checkHeader({ origin: malformedOrigin }, "origin", false)
      ).toBe(false);
      expect(parseSpy).toHaveBeenCalledWith(malformedOrigin, false, true);
    });

    it("should return false from 'isSameOrigin' when the 'origin' header cannot be parsed", async () => {
      await startServer({});

      throwOnMalformedHeaders();

      expect(
        server.isSameOrigin({
          origin: malformedOrigin,
          host: `localhost:${port}`,
        })
      ).toBe(false);
      expect(parseSpy).toHaveBeenCalledWith(malformedOrigin, false, true);
    });

    it("should return false from 'isSameOrigin' when the 'host' header cannot be parsed", async () => {
      await startServer({});

      throwOnMalformedHeaders();

      expect(
        server.isSameOrigin({
          origin: `http://localhost:${port}`,
          host: malformedHost,
        })
      ).toBe(false);
      expect(parseSpy).toHaveBeenCalledWith(`//${malformedHost}`, false, true);
    });

    it("should return false from 'checkHeader' for a 'host' header with a soft hyphen", async () => {
      await startServer({});

      expect(server.checkHeader({ host: "­" }, "host", true)).toBe(false);
      expect(
        server.checkHeader({ origin: "http://­" }, "origin", false)
      ).toBe(false);
      expect(
        server.isSameOrigin({
          origin: "http://­",
          host: `localhost:${port}`,
        })
      ).toBe(false);
    });

    it("should return 'Invalid Host header' for requests with a 'host' header that cannot be parsed", async () => {
      await startServer({});

      throwOnMalformedHeaders();

      const response = await request(server.app)
        .get("/main.js")
        .set("Host", malformedHost);

      expect(response.status).toEqual(200);
      expect(response.text).toEqual("Invalid Host header");
      expect(parseSpy).toHaveBeenCalledWith(`//${malformedHost}`, false, true);
    });

    it("should return 403 from '/webpack-dev-server/invalidate' for an 'origin' header that cannot be parsed", async () => {
      await startServer({});

      throwOnMalformedHeaders();

      const invalidateSpy = jest.spyOn(server, "invalidate");

      const response = await request(server.app)
        .get("/webpack-dev-server/invalidate")
        .set("Host", `localhost:${port}`)
        .set("Origin", malformedOrigin);

      expect(response.status).toEqual(403);
      expect(response.text).toEqual("Cross-Origin request blocked");
      expect(invalidateSpy).not.toHaveBeenCalled();
    });

    it("should reject a web socket connection with an 'origin' header that cannot be parsed without crashing", async () => {
      await startServer({});

      throwOnMalformedHeaders();

      const messages = await connectWebSocket({
        host: `localhost:${port}`,
        origin: malformedOrigin,
      });

      expect(messages).toContainEqual({
        type: "error",
        data: "Invalid Host/Origin header",
      });
      expect(parseSpy).toHaveBeenCalledWith(malformedOrigin, false, true);

      const response = await request(server.app)
        .get("/main.js")
        .set("Host", `localhost:${port}`);

      expect(response.status).toEqual(200);
      expect(response.text).toContain("Hey.");
    });

    it("should reject a web socket connection with a 'host' header that cannot be parsed without crashing", async () => {
      await startServer({});

      throwOnMalformedHeaders();

      const messages = await connectWebSocket({
        host: malformedHost,
        origin: `http://localhost:${port}`,
      });

      expect(messages).toContainEqual({
        type: "error",
        data: "Invalid Host/Origin header",
      });
      expect(parseSpy).toHaveBeenCalledWith(`//${malformedHost}`, false, true);

      const response = await request(server.app)
        .get("/main.js")
        .set("Host", `localhost:${port}`);

      expect(response.status).toEqual(200);
      expect(response.text).toContain("Hey.");
    });
  });
});
