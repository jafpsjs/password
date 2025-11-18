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
  /**
   * For interactive, online operations, `interactive` provide a baseline for these two parameters.
   * Alternatively, `moderate` can be used for more secure operations.
   * For highly sensitive data and non-interactive operations, `sensitive` can be used.
   */
  limit?: HashPasswordLimit;
} | {
  /**
   * The maximum amount of RAM in bytes that the function will use.
   * This number must be between {@link sodium.crypto_pwhash_MEMLIMIT_MIN} and {@link sodium.crypto_pwhash_MEMLIMIT_MAX}.
   */
  memLimit: number;

  /**
   * Represents the maximum amount of computations to perform.
   * Raising this number will make the function require more CPU cycles to compute a key.
   * This number must be between {@link sodium.crypto_pwhash_OPSLIMIT_MIN} and {@link sodium.crypto_pwhash_OPSLIMIT_MAX}.
   */
  opsLimit: number;
};

/**
 * Create a password hash with a random salt.
 *
 * @param password Password to be hashed.
 * @param opts Configuration for {@link sodium.crypto_pwhash_str_async}.
 * @returns he generated hash, settings, salt, version and algorithm will be stored.
 * @see https://libsodium.gitbook.io/doc/password_hashing/default_phf#password-storage
 */
export async function hashPassword(password: string, opts: HashPasswordOptions = {}): Promise<Uint8Array> {
  return await new Promise((resolve, reject) => {
    const outputBuffer = Buffer.alloc(sodium.crypto_pwhash_STRBYTES);
    sodium.crypto_pwhash_str_async(
      outputBuffer,
      Buffer.from(password),
      "opsLimit" in opts ? opts.opsLimit : mapOpsLimit(opts.limit),
      "memLimit" in opts ? opts.memLimit : mapMemLimit(opts.limit),
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
