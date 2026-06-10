import { readFileSync } from "node:fs";
import sharp from "sharp";

const svg = readFileSync(new URL("../icon-src.svg", import.meta.url));
await sharp(svg, { density: 400 })
  .resize(1024, 1024, { fit: "contain", background: { r: 12, g: 18, b: 13, alpha: 1 } })
  .png()
  .toFile(new URL("../icon-src.png", import.meta.url).pathname);
console.log("wrote icon-src.png");
