// Must fail lint: a JWT library in web/.
import { decodeJwt } from "jose";

export const d = decodeJwt;
