import { BigInteger } from "jsbn";
import { params } from "./params";
import { Ephemeral, Session } from "./types";
import { bigIntToHex, randomBigInt } from "./utils";

export const generateSalt = (): string => {
  const s = randomBigInt(params.hashOutputBytes); // User's salt
  return bigIntToHex(s);
};

export const derivePrivateKey = async (
  salt: string,
  username: string,
  password: string,
): Promise<string> => {
  const { H } = params;

  const s = new BigInteger(salt, 16); // User's salt
  const I = username; // Username
  const p = password; // Cleartext Password

  // x = H(s, H(I | ':' | p))
  const x = await H(s, await H(`${I}:${p}`));
  return bigIntToHex(x);
};

export const deriveVerifier = (privateKey: string): string => {
  const { N, g } = params;

  const x = new BigInteger(privateKey, 16); // Private key (derived from p and s)
  const v = g.modPow(x, N); // v = g^x (computes password verifier)
  return bigIntToHex(v);
};

export const generateEphemeral = (): Ephemeral => {
  const { N, g } = params;

  const a = randomBigInt(params.hashOutputBytes);
  const A = g.modPow(a, N); // A = g^a

  return {
    secret: bigIntToHex(a),
    public: bigIntToHex(A),
  };
};

export const deriveSession = async (
  clientSecretEphemeral: string,
  serverPublicEphemeral: string,
  salt: string,
  username: string,
  privateKey: string,
): Promise<Session> => {
  const { N, g, k, H } = params;

  const a = new BigInteger(clientSecretEphemeral, 16); // Secret ephemeral values
  const B = new BigInteger(serverPublicEphemeral, 16); // Public ephemeral values
  const s = new BigInteger(salt, 16); // User's salt
  const I = username; // Username
  const x = new BigInteger(privateKey, 16); // Private key (derived from p and s)

  const A = g.modPow(a, N); // A = g^a

  // B % N > 0
  if (B.mod(N).equals(BigInteger.ZERO)) {
    // fixme: .code, .statusCode, etc.
    throw new Error("The server sent an invalid public ephemeral");
  }

  const [k1, u] = await Promise.all([k, H(A, B)]);

  // S = (B - kg^x) ^ (a + ux)
  const S = B.subtract(k1.multiply(g.modPow(x, N))).modPow(
    a.add(u.multiply(x)),
    N,
  );

  const [K, HN, Hg, HI] = await Promise.all([H(S), H(N), H(g), H(I)]);
  // M = H(H(N) xor H(g), H(I), s, A, B, K)
  const M = await H(HN.xor(Hg), HI, s, A, B, K);

  return {
    key: bigIntToHex(K),
    proof: bigIntToHex(M),
  };
};

export const verifySession = async (
  clientPublicEphemeral: string,
  clientSession: Session,
  serverSessionProof: string,
): Promise<void> => {
  const { H } = params;

  const A = new BigInteger(clientPublicEphemeral, 16); // Public ephemeral values
  const M = new BigInteger(clientSession.proof, 16); // Proof of K
  const K = new BigInteger(clientSession.key, 16); // Shared, strong session key

  const expected = await H(A, M, K);
  const actual = new BigInteger(serverSessionProof, 16);

  if (!actual.equals(expected)) {
    // fixme: .code, .statusCode, etc.
    throw new Error("Server provided session proof is invalid");
  }
};
