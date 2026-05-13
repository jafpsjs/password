# @jafps/password

[![NPM Version](https://img.shields.io/npm/v/%40jafps%2Fpassword)](https://www.npmjs.com/package/@jafps/password)

Functions for hashing and verifying password.

## Usage

```ts
import { verifyPassword, hashPassword } from "@jafps/password";
import { randomUUID } from "node:crypto";

const password = randomUUID();
const hash = await hashPassword(password);
const verifiedResult = await verifyPassword(hash, password);

// Hash with predefined parameters
const hash2 = await hashPassword(password, { limit: "moderate" });
// Hash with custom parameters
const hash3 = await hashPassword(password, { memLimit, opsLimit });
```
