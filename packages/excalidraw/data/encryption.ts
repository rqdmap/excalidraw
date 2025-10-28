// packages/excalidraw/data/encryption.ts
// 注意：当前实现将“禁用”加密（no-op），以保留现有 API 的兼容性。
// 如果将来需要恢复加密，请改为使用后端托管主密钥或启用 envelope encryption（每项数据生成随机对称密钥并由后端 wrap/unwrap）。

import { ENCRYPTION_KEY_BITS } from "../constants";
import { blobToArrayBuffer } from "./blob";

export const IV_LENGTH_BYTES = 12;

// 标记：加密已禁用
export const ENCRYPTION_DISABLED = true;

export const createIV = () => {
  // 返回固定 zero IV（仅为了保持 API 兼容性）
  return new Uint8Array(IV_LENGTH_BYTES);
};

export const generateEncryptionKey = async <T extends "cryptoKey" | "string" = "string">(
  returnAs?: T,
): Promise<T extends "cryptoKey" ? CryptoKey : string> => {
  // 由于禁用加密，返回一个占位字符串或导入一个零密钥以保持调用方类型兼容
  if (returnAs === "cryptoKey") {
    // 导入一个长度与 AES-128/256 兼容的 zero key（仅用于占位/类型兼容）
    const zeroBytes = new Uint8Array(16); // AES-128
    return (await window.crypto.subtle.importKey(
      "raw",
      zeroBytes,
      { name: "AES-GCM" },
      true,
      ["encrypt", "decrypt"],
    )) as any;
  }
  return "NO_ENCRYPTION" as any;
};

export const getCryptoKey = (key: string, usage: KeyUsage) =>
  // 返回一个 zero key（占位），以避免调用方因找不到 key 抛错
  window.crypto.subtle.importKey(
    "raw",
    new Uint8Array(16),
    { name: "AES-GCM" },
    false,
    [usage],
  );

export const encryptData = async (
  key: string | CryptoKey,
  data: Uint8Array | ArrayBuffer | Blob | File | string,
): Promise<{ encryptedBuffer: ArrayBuffer; iv: Uint8Array }> => {
  // No-op: 直接把数据转成 ArrayBuffer 返回，iv 返回 zero IV
  let buffer: ArrayBuffer | Uint8Array;
  if (typeof data === "string") {
    buffer = new TextEncoder().encode(data);
  } else if (data instanceof Blob || data instanceof File) {
    buffer = await blobToArrayBuffer(data);
  } else {
    buffer = data;
  }

  // 返回“伪加密”结果（实际为明文），保持接口不变
  return {
    encryptedBuffer: buffer instanceof ArrayBuffer ? buffer : buffer.buffer,
    iv: createIV(),
  };
};

export const decryptData = async (
  encrypted: Uint8Array | ArrayBuffer,
  privateKey: string,
): Promise<ArrayBuffer> => {
  // No-op: 直接返回输入的 buffer（它本质上是明文）
  return encrypted instanceof ArrayBuffer ? encrypted : encrypted.buffer;
};