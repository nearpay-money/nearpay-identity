/** Migrations directory (`migrations/` next to `dist/` in the image, next to `src/` in the repo). */
import { fileURLToPath } from "node:url";

export const MIGRATIONS_DIR = fileURLToPath(new URL("../../../migrations", import.meta.url));
