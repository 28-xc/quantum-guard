import sharp from 'sharp';
import { readFileSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');
const src = join(root, 'app-icon.png');
const out = join(root, 'app-icon.png');

const buf = readFileSync(src);
const meta = await sharp(buf).metadata();
const w = meta.width || 1;
const h = meta.height || 1;
const size = Math.min(w, h);
const left = Math.floor((w - size) / 2);
const top = Math.floor((h - size) / 2);
const png = await sharp(buf)
  .extract({ left, top, width: size, height: size })
  .png()
  .toBuffer();
writeFileSync(out, png);
console.log('Converted to square PNG: app-icon.png', size, 'x', size);
