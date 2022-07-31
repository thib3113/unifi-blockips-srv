import App from '../src/app';
import Controller, { Site } from 'unifi-client';
import request from 'supertest';

jest.mock('unifi-client');

process.env.UNIFI_CONTROLLER_URL = 'http://127.0.0.1';
process.env.UNIFI_USERNAME = 'UNIFI_USERNAME';
process.env.UNIFI_PASSWORD = 'UNIFI_PASSWORD';
process.env.UNIFI_SITE_NAME = 'default';
process.env.UNIFI_GROUP_NAME = 'UNIFI_GROUP_NAME';
process.env.UNIFI_GROUP_NAME_V6 = 'UNIFI_GROUP_NAME_V6';
const ADD_CHECKSUM = 'ADD_CHECKSUM';
const RM_CHECKSUM = 'RM_CHECKSUM';
process.env.ADD_CHECKSUM = 'd63f8b1d376191c26fd8c3754c96553b7506444206f329a1ad890a6dc2e56051'; //ADD_CHECKSUM
process.env.RM_CHECKSUM = '18debe64e1988e7ce5c659fa7d4118bcbaf25367d0de8b655be7191ffb80fed5'; //RM_CHECKSUM
process.env.PORT = '0';

const ipBans = ['122.228.138.165', '185.108.39.20'];
const ipv6Bans = ['d0fb:a8d5:5803:34b0:a9e9:b77d:4e26:9f1b', 'b432:2512:5e70:1a20:a023:b514:bfb1:7355'];

describe('server', () => {
    let app: App;
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
        },
        {
            action: 'drop',
            dst_firewallgroup_ids: [],
            enabled: true,
            icmpv6_typename: '',
            ipsec: '',
            logging: false,
            name: 'UNIFI_FW_RULE_NAME_V6',
            protocol_match_excepted: false,
            protocol_v6: 'all',
            rule_index: '2502',
            ruleset: 'WANv6_IN',
            site_id: '6001f8a73fd98c05e9465f91',
            src_firewallgroup_ids: ['604bcb9ec3d81805b5f30d83'],
            src_mac_address: '',
            state_established: false,
            state_invalid: false,
            state_new: false,
            state_related: false,
            _id: '60493eb9c3d8180433ef200e'
        }
    ]);
    const getGroupsMock = jest.fn().mockImplementation(() => [
        {
            _id: '604bcb9ec3d81805b5f30d82',
            name: 'UNIFI_GROUP_NAME',
            group_type: 'address-group',
            group_members: ipBans,
            site_id: '6001f8a73fd98c05e9465f91'
        },
        {
            _id: '604bcb9ec3d81805b5f30d82',
            name: 'UNIFI_GROUP_NAME_V6',
            group_type: 'address-group',
            group_members: ipv6Bans,
            site_id: '6001f8a73fd98c05e9465f91'
        }
    ]);
    const loginMock = jest.fn().mockResolvedValue(true);
    beforeEach(async () => {
        jest.useFakeTimers();
        (Controller as jest.Mock).mockImplementationOnce(() => ({
            login: loginMock
        }));

        // @ts-ignore
        const site: Site = {
            _id: '6001f8a73fd98c05e9465f91',
            anonymous_id: 'a3222f4c-3f6f-49f1-a747-ec1afe0fc773',
            name: 'default',
            desc: 'Default',
            attr_hidden_id: 'default',
            attr_no_delete: true,
            role: 'admin',
            role_hotspot: false,
            // @ts-ignore
            firewall: {
                getRules: getRulesMock,
                getGroups: getGroupsMock
            }
        };

        app = new App(site);
        await app.start();
    });
    afterEach(() => {
        return app.kill();
    });
    describe('add an ip', () => {
        it('should add an ip to ban list', async () => {
            // @ts-ignore
            const { server } = app;
            const res = await request(server).post(`?token=${ADD_CHECKSUM}&ips=${ipBans[0]}`).then();
            expect(res.status).toBe(200);
        });
        it("shouldn't add an ip to ban list if token is not good", async () => {
            // @ts-ignore
            const { server } = app;
            const res = await request(server).post(`?token=aaaa&ips=${ipBans[0]}`).then();
            expect(res.status).toBe(401);
        });
    });
    describe('delete an ip', () => {
        it('should delete an ip to ban list', async () => {
            // @ts-ignore
            const { server } = app;
            const res = await request(server).delete(`?token=${RM_CHECKSUM}&ips=${ipBans[0]}`).then();
            expect(res.status).toBe(200);
        });
        it("shouldn't delete an ip to ban list if token is not good", async () => {
            // @ts-ignore
            const { server } = app;
            const res = await request(server).delete(`?token=aaaa&ips=${ipBans[0]}`).then();
            expect(res.status).toBe(401);
        });
    });
});
