/**
 * A software passkey (platform authenticator) for tests: creates "none" attestations and ES256
 * assertions exactly as a browser's `navigator.credentials.create/get` would, so the server-side
 * WebAuthn verification runs unchanged.
 */
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";

// ---- minimal CBOR (maps, byte/text strings, integers) ----------------------------------------
function head(major: number, n: number): Buffer {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  if (n < 65_536) return Buffer.from([(major << 5) | 25, n >> 8, n & 0xff]);
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(n, 1);
  return b;
}
interface CborMap extends Map<number | string, Cbor> {}
interface CborRecord {
  [k: string]: Cbor;
}
type Cbor = number | string | Buffer | CborMap | CborRecord;
function cbor(v: Cbor): Buffer {
  if (typeof v === "number") return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === "string") {
    const b = Buffer.from(v, "utf8");
    return Buffer.concat([head(3, b.length), b]);
  }
  if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v]);
  const entries = v instanceof Map ? [...v.entries()] : Object.entries(v);
  return Buffer.concat([head(5, entries.length), ...entries.flatMap(([k, x]) => [cbor(k), cbor(x)])]);
}

const b64u = (b: Buffer) => b.toString("base64url");
const sha = (b: Buffer | string) => createHash("sha256").update(b).digest();

export interface SoftPasskey {
  readonly credentialId: string;
  create(options: { challenge: string; user: { id: string } }, o?: { origin?: string; uv?: boolean }): RegistrationJSON;
  get(options: { challenge: string }, o?: { origin?: string; uv?: boolean; counter?: number }): AuthenticationJSON;
}

export type RegistrationJSON = {
  id: string;
  rawId: string;
  type: "public-key";
  response: { clientDataJSON: string; attestationObject: string; transports: string[] };
  clientExtensionResults: Record<string, unknown>;
  authenticatorAttachment: string;
};
export type AuthenticationJSON = {
  id: string;
  rawId: string;
  type: "public-key";
  response: { clientDataJSON: string; authenticatorData: string; signature: string; userHandle: string };
  clientExtensionResults: Record<string, unknown>;
  authenticatorAttachment: string;
};

export function softPasskey(rpId: string, defaultOrigin: string): SoftPasskey {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const credId = randomBytes(16);
  let counter = 0;
  let userHandle = "";
  const cose = cbor(
    new Map<number, Cbor>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, Buffer.from(jwk.x, "base64url")],
      [-3, Buffer.from(jwk.y, "base64url")],
    ]),
  );
  const flags = (uv: boolean, at: boolean) => (0x01 | (uv ? 0x04 : 0) | (at ? 0x40 : 0)) & 0xff;
  const count = (n: number) => {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n);
    return b;
  };

  return {
    credentialId: b64u(credId),
    create(options, o = {}) {
      userHandle = options.user.id;
      const clientData = Buffer.from(
        JSON.stringify({
          type: "webauthn.create",
          challenge: options.challenge,
          origin: o.origin ?? defaultOrigin,
          crossOrigin: false,
        }),
      );
      const len = Buffer.alloc(2);
      len.writeUInt16BE(credId.length);
      const authData = Buffer.concat([
        sha(rpId),
        Buffer.from([flags(o.uv ?? true, true)]),
        count(counter),
        Buffer.alloc(16),
        len,
        credId,
        cose,
      ]);
      return {
        id: b64u(credId),
        rawId: b64u(credId),
        type: "public-key",
        response: {
          clientDataJSON: b64u(clientData),
          attestationObject: b64u(cbor({ fmt: "none", attStmt: {}, authData })),
          transports: ["internal"],
        },
        clientExtensionResults: {},
        authenticatorAttachment: "platform",
      };
    },
    get(options, o = {}) {
      // an explicit counter simulates a cloned authenticator; it does not advance this one
      const n = o.counter ?? ++counter;
      const clientData = Buffer.from(
        JSON.stringify({
          type: "webauthn.get",
          challenge: options.challenge,
          origin: o.origin ?? defaultOrigin,
          crossOrigin: false,
        }),
      );
      const authData = Buffer.concat([sha(rpId), Buffer.from([flags(o.uv ?? true, false)]), count(n)]);
      const signature = sign("sha256", Buffer.concat([authData, sha(clientData)]), privateKey);
      return {
        id: b64u(credId),
        rawId: b64u(credId),
        type: "public-key",
        response: {
          clientDataJSON: b64u(clientData),
          authenticatorData: b64u(authData),
          signature: b64u(signature),
          userHandle,
        },
        clientExtensionResults: {},
        authenticatorAttachment: "platform",
      };
    },
  };
}
