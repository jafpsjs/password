# @jafps/password

Functions for hashing and verifying password.

## Usage

```ts
import { verifyPassword, hashPassword } from "@jafps/password";
import { randomUUID } from "node:crypto";

const password = randomUUID();
const hash = await hashPassword(password);
const verifiedResult = await verifyPassword(hash, password);
```
