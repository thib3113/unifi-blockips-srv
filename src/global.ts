import fs from 'fs';
import path from 'path';
import AppRoot from 'app-root-path';
import dotEnv from 'dotenv';

//allow /.env
const envPath = fs.existsSync(path.join('/.env')) ? path.join('/.env') : path.join(AppRoot.path, '.env');

dotEnv.config({
    path: envPath
});

for (const envName of Object.keys(process.env)) {
    if (envName.endsWith('_FILE')) {
        const envNameTarget = envName.slice(0, -5);
        if (!process.env[envNameTarget]) {
            try {
                const filePath = process.env[envName];
                if (filePath && fs.existsSync(filePath)) {
                    process.env[envNameTarget] = fs.readFileSync(filePath, 'utf8').trim();
                }
            } catch (e) {
                console.error(`Error reading ${envNameTarget} from ${envName}: ${e}`);
            }
        }
    }
}
