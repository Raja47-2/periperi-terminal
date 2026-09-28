/**
 * Generate `media/icon.png` from the same mark as `media/icon.svg`.
 *
 * The marketplace icon must be a raster image, but pulling in an SVG rasteriser
 * (sharp, resvg, …) just to bake one file is not worth the dependency, so this
 * writes the PNG by hand: shapes are evaluated per sample with 4x4
 * supersampling and the scanlines are deflated with Node's built-in zlib.
 *
 * Run with `npm run gen:icon`.
 */
import { deflateSync } from 'node:zlib';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SIZE = 128;
const SAMPLES = 4;

const BACKDROP_TOP = [0x1b, 0x10, 0x36];
const BACKDROP_BOTTOM = [0x0b, 0x0b, 0x0d];
const ACCENT = [0x7c, 0x5c, 0xff];
const INK = [0x0b, 0x0b, 0x0d];

/* --------------------------------------------------------------- png writing */

const CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c;
  }
  return table;
})();

function crc32(buffer) {
  let crc = -1;
  for (const byte of buffer) {
    crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ -1) >>> 0;
}

function chunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length, 0);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([length, body, crc]);
}

function encodePng(rgba) {
  const header = Buffer.alloc(13);
  header.writeUInt32BE(SIZE, 0);
  header.writeUInt32BE(SIZE, 4);
  header[8] = 8; // bit depth
  header[9] = 6; // colour type: truecolour with alpha
  header[10] = 0; // deflate
  header[11] = 0; // adaptive filtering
  header[12] = 0; // no interlace

  // Each scanline is prefixed with filter type 0 (None).
  const stride = SIZE * 4;
  const raw = Buffer.alloc((stride + 1) * SIZE);
  for (let y = 0; y < SIZE; y += 1) {
    raw[y * (stride + 1)] = 0;
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }

  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', header),
    chunk('IDAT', deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

/* ------------------------------------------------------------------- shapes */

/** Signed coverage test: true when (x, y) lies inside a rounded rectangle. */
function inRoundedRect(x, y, x0, y0, x1, y1, radius) {
  if (x < x0 || x > x1 || y < y0 || y > y1) {
    return false;
  }
  const cx = Math.min(Math.max(x, x0 + radius), x1 - radius);
  const cy = Math.min(Math.max(y, y0 + radius), y1 - radius);
  const dx = x - cx;
  const dy = y - cy;
  return dx * dx + dy * dy <= radius * radius;
}

function inCircle(x, y, cx, cy, r) {
  const dx = x - cx;
  const dy = y - cy;
  return dx * dx + dy * dy <= r * r;
}

/** The upper half of the shackle: an annulus clipped to y <= cy. */
function inShackle(x, y, cx, cy, outer, inner) {
  if (y > cy) {
    return false;
  }
  const dx = x - cx;
  const dy = y - cy;
  const d2 = dx * dx + dy * dy;
  return d2 <= outer * outer && d2 >= inner * inner;
}

/**
 * Paint one pixel by supersampling `SAMPLES` x `SAMPLES` sub-positions, so
 * the curved edges of the shackle and the keyhole come out smooth.
 */
function paintPixel(pixel, x, y) {
  const step = 1 / SAMPLES;
  const start = (SAMPLES - 1) / 2 / SAMPLES;
  let r = 0;
  let g = 0;
  let b = 0;
  let a = 0;

  for (let sy = 0; sy < SAMPLES; sy += 1) {
    for (let sx = 0; sx < SAMPLES; sx += 1) {
      const px = x + start + sx * step;
      const py = y + start + sy * step;

      let sample;
      if (inCircle(px, py, 64, 76, 8) || inRoundedRect(px, py, 60, 74, 68, 96, 3.5)) {
        // Keyhole sits on top of the body, so it is tested first: these
        // branches are first-match-wins, not painter's order.
        sample = [...INK, 1];
      } else if (inRoundedRect(px, py, 32, 58, 96, 104, 10)) {
        sample = [...ACCENT, 1];
      } else if (inShackle(px, py, 64, 46, 23, 17) || inRoundedRect(px, py, 41, 44, 50, 60, 2) || inRoundedRect(px, py, 78, 44, 87, 60, 2)) {
        sample = [...ACCENT, 1];
      } else if (inRoundedRect(px, py, 0, 0, 128, 128, 24)) {
        // Vertical gradient from deep violet to near-black.
        const t = py / SIZE;
        sample = [
          Math.round(BACKDROP_TOP[0] + (BACKDROP_BOTTOM[0] - BACKDROP_TOP[0]) * t),
          Math.round(BACKDROP_TOP[1] + (BACKDROP_BOTTOM[1] - BACKDROP_TOP[1]) * t),
          Math.round(BACKDROP_TOP[2] + (BACKDROP_BOTTOM[2] - BACKDROP_TOP[2]) * t),
          1,
        ];
      } else {
        sample = [0, 0, 0, 0];
      }

      r += sample[0] * sample[3];
      g += sample[1] * sample[3];
      b += sample[2] * sample[3];
      a += sample[3];
    }
  }

  const total = SAMPLES * SAMPLES;
  if (a === 0) {
    pixel[3] = 0;
    return;
  }
  // Un-premultiply the colour back out of the weighted sums.
  pixel[0] = Math.round(r / a);
  pixel[1] = Math.round(g / a);
  pixel[2] = Math.round(b / a);
  pixel[3] = Math.round((a / total) * 255);
  return pixel;
}

const rgba = Buffer.alloc(SIZE * SIZE * 4);
for (let y = 0; y < SIZE; y += 1) {
  for (let x = 0; x < SIZE; x += 1) {
    const pixel = [0, 0, 0, 0];
    paintPixel(pixel, x, y);
    const offset = (y * SIZE + x) * 4;
    rgba[offset] = pixel[0];
    rgba[offset + 1] = pixel[1];
    rgba[offset + 2] = pixel[2];
    rgba[offset + 3] = pixel[3];
  }
}

const outDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'media');
mkdirSync(outDir, { recursive: true });
const outFile = path.join(outDir, 'icon.png');
writeFileSync(outFile, encodePng(rgba));
console.log(`Wrote ${outFile} (${SIZE}x${SIZE})`);
