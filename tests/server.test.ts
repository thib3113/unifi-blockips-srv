import App from '../src/app';
import Controller from 'unifi-client';
import request from 'supertest';
import axios from 'axios';

jest.mock('unifi-client');
jest.mock('axios');

process.env.UNIFI_CONTROLLER_URL = 'http://127.0.0.1';
process.env.UNIFI_USERNAME = 'UNIFI_USERNAME';
process.env.UNIFI_PASSWORD = 'UNIFI_PASSWORD';
process.env.UNIFI_SITE_NAME = 'default';
process.env.UNIFI_FW_RULE_NAME = 'UNIFI_FW_RULE_NAME';
process.env.UNIFI_GROUP_NAME = 'UNIFI_GROUP_NAME';
const ADD_CHECKSUM = 'ADD_CHECKSUM';
const RM_CHECKSUM = 'RM_CHECKSUM';
process.env.ADD_CHECKSUM = 'd63f8b1d376191c26fd8c3754c96553b7506444206f329a1ad890a6dc2e56051'; //ADD_CHECKSUM
process.env.RM_CHECKSUM = '18debe64e1988e7ce5c659fa7d4118bcbaf25367d0de8b655be7191ffb80fed5'; //RM_CHECKSUM
process.env.PORT = '0';

const ipBans = ['122.228.138.165', '185.108.39.20'];

describe('server', () => {
    let app;
    const mockedAxios = axios as jest.Mocked<typeof axios>;
    const getRulesMock = jest.fn().mockImplementation(() => [
        {
            _id: '60493eb9c3d8180433ef200d',
            ruleset: 'WAN_IN',
            rule_index: 2000,
            name: 'UNIFI_FW_RULE_NAME',
            enabled: true,
            action: 'drop',
            protocol_match_excepted: false,
            logging: true,
            state_new: false,
            state_established: false,
            state_invalid: false,
            state_related: false,
            ipsec: '',
            src_firewallgroup_ids: ['604bcb9ec3d81805b5f30d82'],
            src_mac_address: '',
            dst_firewallgroup_ids: [],
            dst_address: '',
            src_address: '',
            protocol: 'all',
            icmp_typename: '',
            src_networkconf_id: '',
            src_networkconf_type: 'NETv4',
            dst_networkconf_id: '',
            dst_networkconf_type: 'NETv4',
            site_id: '6001f8a73fd98c05e9465f91'
        }
    ]);
    const getGroupsMock = jest.fn().mockImplementation(() => [
        {
            _id: '604bcb9ec3d81805b5f30d82',
            name: 'UNIFI_GROUP_NAME',
            group_type: 'address-group',
            group_members: ipBans,
            site_id: '6001f8a73fd98c05e9465f91'
        }
    ]);
    const getSitesMock = jest.fn().mockImplementation(() => [
        {
            _id: '6001f8a73fd98c05e9465f91',
            anonymous_id: 'a3222f4c-3f6f-49f1-a747-ec1afe0fc773',
            name: 'default',
            desc: 'Default',
            attr_hidden_id: 'default',
            attr_no_delete: true,
            role: 'admin',
            role_hotspot: false,
            firewall: {
                getRules: getRulesMock,
                getGroups: getGroupsMock
            }
        }
    ]);
    const loginMock = jest.fn().mockResolvedValue(true);
    beforeEach(async () => {
        jest.useFakeTimers();
        (Controller as jest.Mock).mockImplementationOnce(() => ({
            getSites: getSitesMock,
            login: loginMock
        }));
        app = new App();
        await app.start();
    });
    afterEach(() => {
        return app.kill();
    });
    describe('add an ip', () => {
        it('should add an ip to ban list', async () => {
            const res = await request(app.server).post(`?token=${ADD_CHECKSUM}&ips=${ipBans[0]}`).then();
            expect(res.status).toBe(200);
        });
        it("shouldn't add an ip to ban list if token is not good", async () => {
            const res = await request(app.server).post(`?token=aaaa&ips=${ipBans[0]}`).then();
            expect(res.status).toBe(401);
        });
    });
    describe('delete an ip', () => {
        it('should delete an ip to ban list', async () => {
            const res = await request(app.server).delete(`?token=${RM_CHECKSUM}&ips=${ipBans[0]}`).then();
            expect(res.status).toBe(200);
        });
        it("shouldn't delete an ip to ban list if token is not good", async () => {
            const res = await request(app.server).delete(`?token=aaaa&ips=${ipBans[0]}`).then();
            expect(res.status).toBe(401);
        });
    });
});
