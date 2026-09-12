import { writeFileSync } from "node:fs";

const [outputPath, ...rest] = process.argv.slice(2);
writeFileSync(outputPath, JSON.stringify(rest));
