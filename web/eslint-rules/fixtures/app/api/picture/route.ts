// Must fail lint: a route handler outside app/%5Fbff/.
export function GET(): Response {
  return new Response("ok");
}
