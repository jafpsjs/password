import sodium from "sodium-native";

export async function verifyPassword(hash: Uint8Array<ArrayBuffer>, password: string): Promise<boolean> {
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
