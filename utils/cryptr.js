import crypto from "crypto";

// function body needs to be synced with the 'encryptOauthToken' function in
// reindex_api/plugins/hosted_data_layer/controller/utils/controller.utils.js
export const encrypt = (text) => {
  const iv = Buffer.from(process.env.AES_IV, "hex");
  const salt = Buffer.from(process.env.AES_SALT, "hex");

  const key = crypto.pbkdf2Sync(
    process.env.AES_MASTER_KEY,
    salt,
    2145,
    32,
    "sha512"
  );
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  const encrypted = Buffer.concat([
    cipher.update(text, "utf8"),
    cipher.final(),
  ]);

  const tag = cipher.getAuthTag();

  return Buffer.concat([salt, iv, tag, encrypted]).toString("hex");
};

// function body needs to be synced with the 'decryptOauthToken' function in
// reindex_api/plugins/hosted_data_layer/controller/utils/controller.utils.js
export const decrypt = (encdata) => {
  const bData = Buffer.from(encdata, "hex");

  const salt = bData.subarray(0, 64);
  const iv = bData.subarray(64, 80);
  const tag = bData.subarray(80, 96);
  const text = bData.subarray(96);

  const key = crypto.pbkdf2Sync(
    process.env.AES_MASTER_KEY,
    salt,
    2145,
    32,
    "sha512"
  );

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);

  const decrypted =
    decipher.update(text, "binary", "utf8") + decipher.final("utf8");

  return decrypted;
};
