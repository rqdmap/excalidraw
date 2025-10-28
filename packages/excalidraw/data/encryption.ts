// src/data/encryption.ts

import { ENCRYPTION_KEY_BITS } from "../constants";
import { blobToArrayBuffer } from "./blob";

export const IV_LENGTH_BYTES = 12;

// 🔑 从环境变量读取主密钥
const MASTER_KEY = import.meta.env.VITE_APP_MASTER_ENCRYPTION_KEY || "";

if (!MASTER_KEY) {
  console.error("⚠️ VITE_APP_MASTER_ENCRYPTION_KEY not set!");
}

export const createIV = () => {
  const arr = new Uint8Array(IV_LENGTH_BYTES);
  return window.crypto.getRandomValues(arr);
};

export const generateEncryptionKey = async <
  T extends "string" | "cryptoKey" = "string",
>(
  returnAs?: T,
): Promise<T extends "cryptoKey" ? CryptoKey : string> => {
  if (returnAs === "cryptoKey") {
    return getCryptoKey(MASTER_KEY, "encrypt") as any;
  }
  return MASTER_KEY as any;
};

export const getCryptoKey = (key: string, usage: KeyUsage) =>
  window.crypto.subtle.importKey(
    "raw",
    Uint8Array.from(atob(key.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
    {
      name: "AES-GCM",
      length: ENCRYPTION_KEY_BITS,
    },
    false, // extractable
    [usage],
  );


export const encryptData = async (
  key: string | CryptoKey,
  data: Uint8Array | ArrayBuffer | Blob | File | string,
): Promise<{ encryptedBuffer: ArrayBuffer; iv: Uint8Array }> => {
  const importedKey = await getCryptoKey(MASTER_KEY, "encrypt");
  const iv = createIV();
  const buffer: ArrayBuffer | Uint8Array =
    typeof data === "string"
      ? new TextEncoder().encode(data)
      : data instanceof Uint8Array
      ? data
      : data instanceof Blob
      ? await blobToArrayBuffer(data)
      : data;

  const encryptedBuffer = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    importedKey,
    buffer as ArrayBuffer | Uint8Array,
  );

  return { encryptedBuffer, iv };
};

export const decryptData = async (
  iv: Uint8Array,
  encrypted: Uint8Array | ArrayBuffer,
  privateKey: string,
): Promise<ArrayBuffer> => {
  const key = await getCryptoKey(MASTER_KEY, "decrypt");
  return window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv,
    },
    key,
    encrypted,
  );
};
