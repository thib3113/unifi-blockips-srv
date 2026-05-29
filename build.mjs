import esbuild from 'esbuild';
import path from 'path';
import fs from 'fs';
import * as url from 'url';
import { execSync } from 'child_process';

const __dirname = url.fileURLToPath(new URL('.', import.meta.url));

const tsConfig = JSON.parse(fs.readFileSync('./tsconfig.json').toString());

const dist = path.join(__dirname, tsConfig.compilerOptions.outDir || 'build');

if (fs.existsSync(dist)) {
    fs.rmSync(dist, { recursive: true, force: true });
}
fs.mkdirSync(dist, { recursive: true });

// Just use __dirname since INIT_CWD might not be reliable
const baseDir = __dirname;
const PACKAGE_JSON_PATH = path.join(baseDir, 'package.json');

const pkg = JSON.parse(fs.readFileSync(PACKAGE_JSON_PATH).toString());

if (!pkg?.name) {
    throw new Error(`fail to read package.json`);
}
fs.writeFileSync(
    path.join(baseDir, 'src', 'pkg.ts'),
    `// THIS FILE IS GENERATED ON BUILD - DO NOT EDIT MANUALLY\nexport const pkg = { name: '${pkg.name}', version: '${pkg.version}' };\n`
);

let makeAllPackagesExternalPlugin = {
    name: 'make-all-packages-external',
    setup(build) {
        let filter = /^[^./]|^\.[^./]|^\.\.[^/]/; // Must not start with "/" or "./" or "../"
        build.onResolve({ filter }, (args) => ({ path: args.path, external: true }));
    }
};

const globalConfig = {
    entryPoints: ['src/index.ts'],
    bundle: true,
    sourcemap: true,
    minify: false,
    plugins: [makeAllPackagesExternalPlugin]
};

Promise.all([
    esbuild.build({
        ...globalConfig,
        outdir: path.join(dist, 'esm'),
        splitting: true,
        format: 'esm',
        outExtension: { '.js': '.mjs' },
        target: ['esnext']
    }),
    esbuild.build({
        ...globalConfig,
        outdir: path.join(dist, 'cjs'),
        format: 'cjs',
        outExtension: { '.js': '.cjs' },
        platform: 'node',
        target: ['node16']
    })
]).then(() => {
    // an entry file for cjs at the root of the bundle
    fs.writeFileSync(path.join(dist, 'index.mjs'), "export * from './esm/index.mjs';\n");

    // an entry file for esm at the root of the bundle
    fs.writeFileSync(path.join(dist, 'index.cjs'), "module.exports = require('./cjs/index.cjs');\n");
    fs.writeFileSync(path.join(dist, 'index.js'), "module.exports = require('./cjs/index.cjs');\n");

    // We can run tsc from this script to output declarations
    try {
        execSync('npx tsc --project tsconfig.json --declaration --emitDeclarationOnly --outDir ' + path.join(dist, 'types'), { stdio: 'inherit' });
    } catch (e) {
        // Handle gracefully if this is a project that doesn't need to export types
        // Or if tsc fails for some reason
        console.warn('Failed to emit typescript declarations');
    }

    if (fs.existsSync(path.join(dist, 'types', 'index.d.ts'))) {
        fs.writeFileSync(path.join(dist, 'index.d.ts'), "export * from './types/index.js';\n");
        fs.writeFileSync(path.join(dist, 'index.d.cts'), "export * from './types/index.js';\n");
    }
}).catch((e) => {
    console.error(e);
    process.exit(1);
});
