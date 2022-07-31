import * as path from 'path';
import dotEnv from 'dotenv';
import App from '../src/app';

jest.mock('unifi-client');

dotEnv.config({
    path: path.join(__dirname, '..', '.env')
});

//random port
process.env.PORT = '0';

describe('global tests', () => {
    describe('try constructor', () => {
        it('test full env', () => {
            process.env.UNIFI_CONTROLLER_URL = 'UNIFI_CONTROLLER_URL';
            process.env.UNIFI_USERNAME = 'UNIFI_USERNAME';
            process.env.UNIFI_PASSWORD = 'UNIFI_PASSWORD';
            process.env.UNIFI_SITE_NAME = 'UNIFI_SITE_NAME';
            process.env.UNIFI_FW_RULE_NAME = 'UNIFI_FW_RULE_NAME';
            process.env.UNIFI_GROUP_NAME = 'UNIFI_GROUP_NAME, UNIFI_GROUP_NAME2';
            process.env.ADD_CHECKSUM = 'ADD_CHECKSUM';
            process.env.RM_CHECKSUM = 'RM_CHECKSUM';
            process.env.PORT = '9999';
            // @ts-ignore
            const app = new App();

            // @ts-ignore
            expect(app.unifiFWGroupNames).toStrictEqual(['UNIFI_GROUP_NAME', 'UNIFI_GROUP_NAME2']);
            // @ts-ignore
            expect(app.addCheckSum).toBe('ADD_CHECKSUM');
            // @ts-ignore
            expect(app.rmCheckSum).toBe('RM_CHECKSUM');
            // @ts-ignore
            expect(app.port).toBe(9999);
        });
    });
});
