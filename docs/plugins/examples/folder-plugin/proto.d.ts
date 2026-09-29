// `bun` resolves `import x from "./file" with { type: "file" }` to a path; this
// tells tsc the same thing for `.proto`.
declare module "*.proto" {
  const path: string;
  export default path;
}
