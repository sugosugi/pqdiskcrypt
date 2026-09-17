/* Minimal faithful shim for @noble/curves/utils.js `abool`, the ONLY symbol
   ml-dsa.js imports from that module. ml-dsa calls abool(value, title) solely
   to validate the optional `externalMu` flag, which pqfilecrypt never sets, so
   this is never invoked at runtime. Kept strict to match upstream behaviour. */
export function abool(value, title) {
  if (typeof value !== "boolean")
    throw new Error((title || "value") + " expected boolean, got " + typeof value);
}
