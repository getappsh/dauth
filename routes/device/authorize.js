import RateLimit from "@fastify/rate-limit";
import { customAlphabet } from "nanoid";
import { eq } from "drizzle-orm";
import { oauth_clients, oauth_devices } from "../../db/schemas.js";
import {
  deviceError,
  deviceAuthorizeSuccess,
} from "../../utils/payloadSchemas.js";

export default async function Authorize(fastify) {
  const generateDeviceCode = customAlphabet(
    "0123456789BCDFGHJKLMNPQRSTVWXZbcdfghjklmnpqrstvwxz",
    40
  );
  const generateUserCode = customAlphabet("BCDFGHJKLMNPQRSTVWXZ", 8);

  const schema = {
    schema: {
      response: {
        200: deviceAuthorizeSuccess,
        "4xx": deviceError,
        500: deviceError,
      },
    },
  };

  await fastify.register(RateLimit, {
    max: 1,
    timeWindow: 1000,
    errorResponseBuilder: () => {
      return {
        statusCode: 429,
        error: "slow_down",
        error_description: "rate limit is one request per second",
      };
    },
  });

  fastify.post("/authorize", schema, async (request, reply) => {
    const { client_id, state } = request.body;

    if (!client_id) {
      return reply.code(400).send({
        error: "incorrect_client_credentials",
        error_description: "property 'client_id' can not be empty",
      });
    }

    if (!fastify?.db?.query?.oauth_clients) {
      return reply.code(500).send({
        error: "incorrect_client_credentials",
        error_description: "cannot check 'client_id'",
      });
    }

    const foundClient = await fastify.db.query.oauth_clients.findFirst({
      where: eq(oauth_clients.id, client_id),
    });

    if (!foundClient) {
      return reply.code(400).send({
        error: "incorrect_client_credentials",
        error_description: `client with id ${client_id} does not exist`,
      });
    }

    if (!foundClient?.active) {
      return reply.code(400).send({
        error: "incorrect_client_credentials",
        error_description: `client with id ${client_id} is not active`,
      });
    }

    const userCode = generateUserCode();
    const deviceCode = generateDeviceCode();
    const expiresAt =
      Date.now() + Number(process.env.OAUTH_DEVICE_CODE_EXPIRES_IN) * 1000;

    try {
      // save generated device
      await fastify.db.insert(oauth_devices).values({
        deviceCode,
        userCode,
        expiresAt: new Date(expiresAt),
        clientId: client_id,
      });

      const response = {
        device_code: deviceCode,
        user_code: userCode,
        verification_uri: `${process.env.OAUTH_DEVICE_VERIFICATION_BASE_URL}/login/device`,
        verification_uri_complete: `${process.env.OAUTH_DEVICE_VERIFICATION_BASE_URL}/login/device?user_code=${userCode}`,
        expires_in: process.env.OAUTH_DEVICE_CODE_EXPIRES_IN,
        interval: process.env.OAUTH_DEVICE_AUTHORIZE_INTERVAL,
      };

      if (state) {
        response.state = state;
      }

      return reply.send(response);
    } catch (error) {
      return reply.code(500).send({
        error: "device_code_save_error",
        error_description: error?.message || "cannot save device code",
      });
    }
  });
}
