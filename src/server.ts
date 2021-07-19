import { BigInteger } from "jsbn";
import { params } from "./params";
import { Ephemeral, Session } from "./types";
import { bigIntToHex, randomBigInt } from "./utils";

export const generateEphemeral = async (
  verifier: string,
): Promise<Ephemeral> => {
  const { N, g, k } = params;

  const v = new BigInteger(verifier, 16); // Password verifier
  const b = randomBigInt(params.hashOutputBytes);
  const B = (await k).multiply(v).add(g.modPow(b, N)).mod(N); // B = kv + g^b

  return {
    secret: bigIntToHex(b),
    public: bigIntToHex(B),
  };
};

export const deriveSession = async (
  serverSecretEphemeral: string,
  clientPublicEphemeral: string,
  salt: string,
  username: string,
  verifier: string,
  clientSessionProof: string,
): Promise<Session> => {
  const { N, g, k, H } = params;

  const b = new BigInteger(serverSecretEphemeral, 16); // Secret ephemeral values
  const A = new BigInteger(clientPublicEphemeral, 16); // Public ephemeral values
  const s = new BigInteger(salt, 16); // User's salt
  const I = username; // Username
  const v = new BigInteger(verifier, 16); // Password verifier

  const B = (await k).multiply(v).add(g.modPow(b, N)).mod(N); // B = kv + g^b

  // A % N > 0
  if (A.mod(N).equals(BigInteger.ZERO)) {
    // fixme: .code, .statusCode, etc.
    throw new Error("The client sent an invalid public ephemeral");
  }

  const u = await H(A, B);
  const S = A.multiply(v.modPow(u, N)).modPow(b, N); // S = (Av^u) ^ b (computes session key)

  const [K, HN, Hg, HI] = await Promise.all([H(S), H(N), H(g), H(I)]);

  // M = H(H(N) xor H(g), H(I), s, A, B, K)
  const M = await H(HN.xor(Hg), HI, s, A, B, K);

  const expected = M;
  const actual = new BigInteger(clientSessionProof, 16);

  if (!actual.equals(expected)) {
    // fixme: .code, .statusCode, etc.
    throw new Error("Client provided session proof is invalid");
  }

  const P = await H(A, M, K);

  return {
    key: bigIntToHex(K),
    proof: bigIntToHex(P),
  };
};
