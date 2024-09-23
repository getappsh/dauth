import {
  mysqlTable,
  text,
  tinyint,
  int,
  datetime,
} from "drizzle-orm/mysql-core";

export const oauth_clients = mysqlTable("o_auth_clients", {
  id: text("id"),
  active: tinyint("active"),
});

export const oauth_devices = mysqlTable("o_auth_devices", {
  deviceCode: text("deviceCode"),
  userCode: text("userCode"),
  expiresAt: datetime("expiresAt"),
  verifiedAt: datetime("verifiedAt"),
  deniedAt: datetime("deniedAt"),
  clientId: text("clientId"),
  userId: text("userId"),
});

export const oauth_access_tokens = mysqlTable("o_auth_access_tokens", {
  token: text("token"),
  refreshTokenId: int("refreshTokenId"),
  createdAt: datetime("createdAt"),
  expiresAt: datetime("expiresAt"),
  clientId: text("clientId"),
  userId: text("userId"),
});

export const oauth_refresh_tokens = mysqlTable("o_auth_refresh_tokens", {
  id: int("id"),
  token: text("token"),
  createdAt: datetime("createdAt"),
  expiresAt: datetime("expiresAt"),
  clientId: text("clientId"),
  userId: text("userId"),
});
