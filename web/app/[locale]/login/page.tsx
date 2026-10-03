import { LoginPage } from "@/src/login/LoginPage";

// The console's sign-in: the password, then the TOTP code, through the
// BFF's /_bff/login (docs/runbooks/session-contract.md).
export default function Login() {
  return <LoginPage />;
}
