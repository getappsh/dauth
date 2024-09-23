export const deviceError = {
  type: "object",
  properties: {
    error: {
      type: "string",
    },
    error_description: {
      type: "string",
    },
  },
};

export const deviceAuthorizeSuccess = {
  type: "object",
  properties: {
    device_code: {
      type: "string",
    },
    user_code: {
      type: "string",
    },
    verification_uri: {
      type: "string",
    },
    verification_uri_complete: {
      type: "string",
    },
    expires_in: {
      type: "number",
    },
    interval: {
      type: "number",
    },
    state: {
      type: "string",
    },
  },
};

export const deviceTokenSuccess = {
  type: "object",
  properties: {
    access_token: {
      type: "string",
    },
    expires_in: {
      type: "number",
    },
    refresh_token: {
      type: "string",
    },
    refresh_token_expires_in: {
      type: "number",
    },
    token_type: {
      type: "string",
    },
    state: {
      type: "string",
    },
  },
};

export const deviceAuthorizeRequestPayload = {
  type: "object",
  required: ["client_id"],
  properties: {
    client_id: {
      type: "string",
    },
    scope: {
      type: "string",
    },
    state: {
      type: "string",
    },
  },
};

export const deviceTokenRequestPayload = {
  type: "object",
  required: ["grant_type"],
  properties: {
    client_id: {
      type: "string",
    },
    grant_type: {
      type: "string",
    },
    device_code: {
      type: "string",
    },
    state: {
      type: "string",
    },
  },
};
