// https://github.com/LinusU/array-buffer-to-hex
// https://github.com/LinusU/hex-to-array-buffer
// https://github.com/wbinnssmith/arraybuffer-equal

export const bufferEqual = (
  bufferA: ArrayBufferLike,
  bufferB: ArrayBufferLike,
): boolean => {
  if (bufferA === bufferB) {
    return true;
  }
  if (bufferA.byteLength !== bufferB.byteLength) {
    return false;
  }

  let viewA = new DataView(bufferA);
  let viewB = new DataView(bufferB);

  let i = bufferA.byteLength;

  while (i--) {
    if (viewA.getUint8(i) !== viewB.getUint8(i)) {
      return false;
    }
  }

  return true;
};

export const bufferToHex = (buffer: ArrayBufferLike): string => {
  const view = new Uint8Array(buffer);
  let result = "";

  for (let index = 0; index < view.length; index++) {
    result += view[index].toString(16).padStart(2, "0");
  }

  return result;
};

export const hexToBuffer = (hex: string): ArrayBufferLike => {
  const length = Math.ceil(hex.length / 2);
  const view = new Uint8Array(length);

  for (let index = 0; index < length; index++) {
    view[index] = parseInt(hex.substr(index * 2, 2).padStart(2, "0"), 16);
  }

  return view.buffer;
};
