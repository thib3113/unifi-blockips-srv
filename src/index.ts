import App from './app';
import dotEnv from 'dotenv';
import AppRoot from 'app-root-path';
import path from 'path';
import fs from 'fs';

//allow /.env
const envPath = fs.existsSync(path.join('/.env')) ? path.join('/.env') : path.join(AppRoot.path, '.env');

dotEnv.config({
    path: envPath
});

try {
    new App().start().catch((e) => console.error(e));
} catch (e) {
    console.error(e);
    throw e;
}

process.on('unhandledRejection', (reason, p) => {
    console.log('Unhandled Rejection at: Promise', p, 'reason:', reason);
    // application specific logging, throwing an error, or other logic here
});
