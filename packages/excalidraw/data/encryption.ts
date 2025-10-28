import { ENCRYPTION_KEY_BITS } from "../constants";
import { blobToArrayBuffer } from "./blob";

export const IV_LENGTH_BYTES = 12;

export const createIV = () => {
  return new Uint8Array(IV_LENGTH_BYTES); // 返回全零数组
};

export const generateEncryptionKey = async <
  T extends "string" | "cryptoKey" = "string",
>(
  returnAs?: T,
): Promise<T extends "cryptoKey" ? CryptoKey : string> => {
  if (returnAs === "cryptoKey") {
    // 创建一个虚拟的 CryptoKey
    const keyData = new Uint8Array(16); // 128位密钥
    const key = await window.crypto.subtle.importKey(
      "raw",
      keyData,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
    return key as T extends "cryptoKey" ? CryptoKey : string;
  } else {
    return "dummy-key-12345678" as T extends "cryptoKey" ? CryptoKey : string;
  }
};

export const getCryptoKey = async (key: string, usage: KeyUsage) => {
  // 创建一个固定的 128 位密钥
  const keyData = new Uint8Array(16);
  return await window.crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "AES-GCM" },
    false,
    [usage]
  );
};

export const encryptData = async (
  key: string | CryptoKey,
  data: Uint8Array | ArrayBuffer | Blob | File | string,
): Promise<{ encryptedBuffer: ArrayBuffer; iv: Uint8Array }> => {
  const iv = createIV();

  let buffer: ArrayBuffer;

  if (typeof data === "string") {
    buffer = new TextEncoder().encode(data).buffer;
  } else if (data instanceof Uint8Array) {
    buffer = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
  } else if (data instanceof Blob) {
    buffer = await blobToArrayBuffer(data);
  } else {
    buffer = data;
  }

  // 直接返回原始数据，不加密
  return { encryptedBuffer: buffer, iv };
};

export const decryptData = async (
  iv: Uint8Array,
  encrypted: Uint8Array | ArrayBuffer,
  privateKey: string,
): Promise<ArrayBuffer> => {
  // 直接返回原始数据，不解密
  if (encrypted instanceof Uint8Array) {
    return encrypted.buffer.slice(encrypted.byteOffset, encrypted.byteOffset + encrypted.byteLength);
  }
  return encrypted;
};

