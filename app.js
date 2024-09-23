import RateLimit from "@fastify/rate-limit";

export default async (fastify, opts) => {
  await fastify.register(import("@fastify/compress"));

  fastify.register(import("@fastify/sensible"));
  fastify.register(import("@fastify/formbody"));
  fastify.register(import("@fastify/helmet"), { global: true });

  fastify.removeContentTypeParser(["application/json"]);

  fastify.register(async (server) => {
    await fastify.register(RateLimit, {
      max: 1,
      timeWindow: 1000,
    });

    server.get("/healthcheck", { logLevel: "silent" }, (request, reply) => {
      if (!request.headers["x-linnovate-healthcheck"]) {
        throw fastify.httpErrors.unauthorized();
      }

      return reply.send();
    });
  });

  fastify.register(import("./db/db-plugin.js"));

  fastify.register(
    async function OAuth2Context(server) {
      server.register(
        async function DeviceContext(server) {
          server.register(import(`./routes/device/authorize.js`));
          server.register(import(`./routes/device/token.js`));
        },
        {
          prefix: "/device",
        }
      );
    },
    {
      prefix: "/oauth2",
    }
  );
};
