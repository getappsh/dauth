import RateLimit from "@fastify/rate-limit";
import { eq, and, gt } from "drizzle-orm";
import { decrypt } from "../../utils/cryptr.js";
import { deviceError, deviceTokenSuccess } from "../../utils/payloadSchemas.js";
import {
  oauth_clients,
  oauth_devices,
  oauth_access_tokens,
  oauth_refresh_tokens,
} from "../../db/schemas.js";

export default async function Token(fastify) {
  const schema = {
    schema: {
      response: {
        200: deviceTokenSuccess,
        "4xx": deviceError,
        500: deviceError,
      },
    },
  };

  const handleDeviceCodeGrant = async (body) => {
    ["client_id", "grant_type", "device_code"].forEach((property) => {
      if (!body[property]) {
        return {
          statusCode: 400,
          data: {
            error: "incorrect_payload",
            error_description: `property '${property}' can not be empty`,
          },
        };
      }
    });

    const { client_id, device_code, state } = body;

    if (!fastify?.db?.query?.oauth_clients) {
      return {
        statusCode: 500,
        data: {
          error: "incorrect_client_credentials",
          error_description: "cannot check 'client_id'",
        },
      };
    }

    const foundClient = await fastify.db.query.oauth_clients.findFirst({
      where: eq(oauth_clients.id, client_id),
    });

    if (!foundClient) {
      return {
        statusCode: 400,
        data: {
          error: "incorrect_client_credentials",
          error_description: "client credentials cannot be verified",
        },
      };
    }

    if (!foundClient?.active) {
      return {
        statusCode: 400,
        data: {
          error: "incorrect_client_credentials",
          error_description: `client with id ${client_id} is not active`,
        },
      };
    }

    const foundDevice = await fastify.db.query.oauth_devices.findFirst({
      where: eq(oauth_devices.deviceCode, device_code),
    });

    if (!foundDevice) {
      return {
        statusCode: 400,
        data: {
          error: "incorrect_device_code",
          error_description: "device code cannot be verified",
        },
      };
    }

    const { clientId, expiresAt, verifiedAt, deniedAt } = foundDevice;

    if (clientId !== client_id) {
      return {
        statusCode: 400,
        data: {
          error: "incorrect_client_credentials",
          error_description: "client credentials are not valid",
        },
      };
    }

    if (new Date() > expiresAt) {
      return {
        statusCode: 400,
        data: {
          error: "expired_token",
          error_description: "device code has expired",
        },
      };
    }

    if (deniedAt) {
      return {
        statusCode: 400,
        data: {
          error: "access_denied",
          error_description: "authorization request was denied",
        },
      };
    }

    if (verifiedAt) {
      const { userId } = foundDevice;

      if (!userId) {
        return {
          statusCode: 400,
          data: {
            error: "unauthorized_device",
            error_description: "cannot retrieve authorized user",
          },
        };
      }

      if (new Date() <= expiresAt) {
        // get access_token for userId
        const accessToken =
          await fastify.db.query.oauth_access_tokens.findFirst({
            where: and(
              eq(oauth_access_tokens.userId, userId),
              eq(oauth_access_tokens.clientId, clientId),
              gt(oauth_access_tokens.expiresAt, new Date())
            ),
          });

        const refreshToken =
          await fastify.db.query.oauth_refresh_tokens.findFirst({
            where: eq(oauth_refresh_tokens.id, accessToken.refreshTokenId),
          });

        if (!accessToken || !refreshToken) {
          return {
            statusCode: 500,
            data: {
              error: "missing_token",
              error_description: "cannot retrieve token information",
            },
          };
        }

        const response = {
          statusCode: 200,
          data: {
            access_token: decrypt(accessToken.token),
            refresh_token: decrypt(refreshToken.token),
            token_type: "bearer",
            expires_in: Number(
              process.env.OAUTH_DEVICE_ACCESS_TOKEN_EXPIRES_IN
            ),
            refresh_token_expires_in: Number(
              process.env.OAUTH_DEVICE_REFRESH_TOKEN_EXPIRES_IN
            ),
          },
        };

        if (state) {
          response.data.state = state;
        }

        return response;
      }
    }

    return {
      statusCode: 400,
      data: {
        error: "authorization_pending",
        error_description: "user has not authorized device yet",
      },
    };
  };

  const handleRefreshTokenGrant = async (body) => {
    const apiCall = await fetch(
      `${process.env.HOSTED_DATA_LAYER_URL}/oauth/refresh_token`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
      }
    );

    const apiResponse = await apiCall.json();

    if (apiResponse?.success) {
      const response = {
        statusCode: 200,
        data: {
          access_token: apiResponse?.data?.access_token,
          refresh_token: apiResponse?.data?.refresh_token,
          token_type: "bearer",
          expires_in: Number(process.env.OAUTH_DEVICE_ACCESS_TOKEN_EXPIRES_IN),
          refresh_token_expires_in: Number(
            process.env.OAUTH_DEVICE_REFRESH_TOKEN_EXPIRES_IN
          ),
        },
      };

      if (body?.state) {
        response.data.state = body.state;
      }

      return response;
    } else {
      return {
        statusCode: 400,
        data: {
          error: "error_refreshing_token",
          error_description: apiResponse?.message || "failed to refresh token",
        },
      };
    }
  };

  await fastify.register(RateLimit, {
    max: 1,
    timeWindow: process.env.OAUTH_DEVICE_AUTHORIZE_INTERVAL * 1000,
    errorResponseBuilder: () => {
      return {
        statusCode: 429,
        error: "slow_down",
        error_description: `rate limit is one request every ${process.env.OAUTH_DEVICE_AUTHORIZE_INTERVAL} seconds`,
      };
    },
  });

  fastify.post("/token", schema, async (request, reply) => {
    let response;

    const { grant_type } = request?.body;

    if (!grant_type) {
      return reply.code(400).send({
        error: "unsupported_grant_type",
        error_description: `grant '${grant_type}' is not supported`,
      });
    }

    try {
      switch (grant_type) {
        case "urn:ietf:params:oauth:grant-type:device_code":
          response = await handleDeviceCodeGrant(request.body);
          break;

        case "refresh_token":
          response = await handleRefreshTokenGrant(request.body);
          break;
      }
    } catch (error) {
      request.log.debug(error, "error processing token request");

      response = {
        statusCode: 500,
        data: {
          error: "unknown_error",
          error_description: "cannot handle request",
        },
      };
    }

    return reply.code(response.statusCode).send(response.data);
  });
}
