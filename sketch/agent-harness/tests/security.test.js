const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'src', 'cli.js');
const OUTPUT_DIR = path.join(ROOT, 'output', 'security-test');

beforeAll(() => {
  if (!fs.existsSync(OUTPUT_DIR)) {
    fs.mkdirSync(OUTPUT_DIR, { recursive: true });
  }
});

afterAll(() => {
  if (fs.existsSync(OUTPUT_DIR)) {
    fs.rmSync(OUTPUT_DIR, { recursive: true, force: true });
  }
});

describe('sketch-cli security', () => {
  test('allows tokens in folders starting with dots (..brand)', () => {
    const specDir = path.join(OUTPUT_DIR, 'spec');
    const brandDir = path.join(specDir, '..brand');
    fs.mkdirSync(brandDir, { recursive: true });
    
    const tokensPath = path.join(brandDir, 'tokens.json');
    const tokens = { colors: { primary: '#ff0000' } };
    fs.writeFileSync(tokensPath, JSON.stringify(tokens));

    const inputPath = path.join(specDir, 'design.json');
    const design = {
      pages: [{ do_objectID: 'page1', layers: [], artboards: [] }],
      tokens: './..brand/tokens.json'
    };
    fs.writeFileSync(inputPath, JSON.stringify(design));

    const outputPath = path.join(OUTPUT_DIR, 'out.sketch');
    
    const result = execSync(
      `node "${CLI}" build --input "${inputPath}" --output "${outputPath}" 2>&1`,
      { encoding: 'utf-8', cwd: ROOT }
    );
    
    expect(result).toContain('Done!');
    expect(result).not.toContain('Unsafe spec tokens path ignored');
  });

  test('blocks tokens outside the spec directory', () => {
    const specDir = path.join(OUTPUT_DIR, 'spec-unsafe');
    fs.mkdirSync(specDir, { recursive: true });
    
    const unsafeTokensPath = path.join(OUTPUT_DIR, 'unsafe-tokens.json');
    const tokens = { colors: { primary: '#00ff00' } };
    fs.writeFileSync(unsafeTokensPath, JSON.stringify(tokens));

    const inputPath = path.join(specDir, 'design.json');
    const design = {
      pages: [{ do_objectID: 'page1', layers: [], artboards: [] }],
      tokens: '../../unsafe-tokens.json'
    };
    fs.writeFileSync(inputPath, JSON.stringify(design));

    const outputPath = path.join(OUTPUT_DIR, 'out-unsafe.sketch');
    
    const result = execSync(
      `node "${CLI}" build --input "${inputPath}" --output "${outputPath}" 2>&1`,
      { encoding: 'utf-8', cwd: ROOT }
    );
    
    expect(result).toContain('Unsafe spec tokens path ignored');
  });

  test('blocks symlinks pointing outside the spec directory', () => {
    const specDir = path.join(OUTPUT_DIR, 'spec-symlink');
    fs.mkdirSync(specDir, { recursive: true });
    
    const secretPath = path.join(OUTPUT_DIR, 'secret.json');
    fs.writeFileSync(secretPath, JSON.stringify({ secret: 'ssh-key' }));

    const symlinkPath = path.join(specDir, 'malicious-link.json');
    try {
      fs.symlinkSync(secretPath, symlinkPath);
    } catch (e) {
      console.warn('Skipping symlink test: symlinks not supported/permitted');
      return;
    }

    const inputPath = path.join(specDir, 'design.json');
    const design = {
      pages: [{ do_objectID: 'page1', layers: [], artboards: [] }],
      tokens: './malicious-link.json'
    };
    fs.writeFileSync(inputPath, JSON.stringify(design));

    const outputPath = path.join(OUTPUT_DIR, 'out-symlink.sketch');
    
    const result = execSync(
      `node "${CLI}" build --input "${inputPath}" --output "${outputPath}" 2>&1`,
      { encoding: 'utf-8', cwd: ROOT }
    );
    
    expect(result).toContain('Unsafe spec tokens path ignored');
  });
});
