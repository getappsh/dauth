import fp from "fastify-plugin";
import db from "./client.js";

export default fp(async (fastify) => {
  fastify.decorate("db", db);
});
