import sodium from "sodium-native";
// eslint-disable-next-line @typescript-eslint/no-unused-vars
import type { hashPassword } from "./hash-password.js";

/**
 * Verify a password hash generated with {@link hashPassword}.
 *
 * @param hash Buffer with generated with {@link hashPassword}.
 * @param password Password to be verified.
 * @returns `true` if the hash could be verified with the settings contained in str. Otherwise `false`.
 * @see https://libsodium.gitbook.io/doc/password_hashing/default_phf#password-storage
 */
export async function verifyPassword(hash: Uint8Array, password: string): Promise<boolean> {
  return await new Promise((resolve, reject) => {
    sodium.crypto_pwhash_str_verify_async(
      Buffer.from(hash),
      Buffer.from(password),
      (err, result) => {
        if (err) {
          reject(err);
        } else {
          resolve(result);
        }
      }
    );
  });
}
