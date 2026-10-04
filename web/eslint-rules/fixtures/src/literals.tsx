// Must fail lint: display text outside the catalogue (the pair: twin-literals.tsx).
export function Hello() {
  return <p aria-label="Aircraft">Hello</p>;
}
