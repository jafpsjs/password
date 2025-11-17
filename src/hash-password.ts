import sodium from "sodium-native";

export type HashPasswordLimit = "interactive" | "min" | "moderate" | "sensitive";

function mapOpsLimit(opsLimit?: HashPasswordLimit): number {
  switch (opsLimit) {
    case "interactive":
      return sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE;
    case "min":
      return sodium.crypto_pwhash_OPSLIMIT_MIN;
    case "moderate":
      return sodium.crypto_pwhash_OPSLIMIT_MODERATE;
    case "sensitive":
      return sodium.crypto_pwhash_OPSLIMIT_SENSITIVE;
    default:
      return sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE;
  }
}

function mapMemLimit(memLimit?: HashPasswordLimit): number {
  switch (memLimit) {
    case "interactive":
      return sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE;
    case "min":
      return sodium.crypto_pwhash_MEMLIMIT_MIN;
    case "moderate":
      return sodium.crypto_pwhash_MEMLIMIT_MODERATE;
    case "sensitive":
      return sodium.crypto_pwhash_MEMLIMIT_SENSITIVE;
    default:
      return sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE;
  }
}

export type HashPasswordOptions = {
  limit?: HashPasswordLimit;
};

export async function hashPassword(password: string, opts: HashPasswordOptions = {}): Promise<Uint8Array<ArrayBuffer>> {
  const { limit } = opts;
  return await new Promise((resolve, reject) => {
    const outputBuffer = Buffer.alloc(sodium.crypto_pwhash_STRBYTES);
    sodium.crypto_pwhash_str_async(
      outputBuffer,
      Buffer.from(password),
      mapOpsLimit(limit),
      mapMemLimit(limit),
      err => {
        if (err) {
          reject(err);
        } else {
          resolve(new Uint8Array(outputBuffer));
        }
      }
    );
  });
}
