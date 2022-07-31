import fs from 'fs';
import path from 'path';
import AppRoot from 'app-root-path';
import dotEnv from 'dotenv';

//allow /.env
const envPath = fs.existsSync(path.join('/.env')) ? path.join('/.env') : path.join(AppRoot.path, '.env');

dotEnv.config({
    path: envPath
});
