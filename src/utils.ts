import { BigInteger } from "jsbn";
import { bufferToHex } from "./buffer";
import { crypto } from "./crypto";

export const randomBigInt = (bytes: number): BigInteger => {
  const view = new Uint8Array(bytes);
  crypto.getRandomValues(view);
  return new BigInteger(bufferToHex(view.buffer), 16);
};

export const bigIntToArrayBuffer = (n: BigInteger): ArrayBuffer => {
  const hex = n.toString(16);
  const arrayBuffer = new ArrayBuffer(Math.ceil(hex.length / 2));
  const u8 = new Uint8Array(arrayBuffer);
  let offset = 0;
  // handle toString(16) not padding
  if (hex.length % 2 !== 0) {
    u8[0] = parseInt(hex[0], 16);
    offset = 1;
  }
  for (let i = 0; i < arrayBuffer.byteLength; i++) {
    u8[i + offset] = parseInt(
      hex.slice(2 * i + offset, 2 * i + 2 + offset),
      16,
    );
  }
  return arrayBuffer;
};

export const bigIntToHex = (input: BigInteger): string => {
  const arrayBuffer = bigIntToArrayBuffer(input);
  return bufferToHex(arrayBuffer);
};
