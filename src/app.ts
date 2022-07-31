import Controller, { FWGroup, Site } from 'unifi-client';
import express, { Express } from 'express';
import * as crypto from 'crypto';
import { TasksBuffer } from './TasksBuffer';
import * as http from 'http';
import { Address4, Address6 } from 'ip-address';
import { AddressInfo } from 'net';
import logger from './logger';

const MAX_IPS_PER_GROUP = 10000;

const enum EMethods {
    ADD,
    DEL
}

export default class App {
    private readonly unifiFWGroupNames: Array<string>;
    private readonly unifiFWGroupNamesV6: Array<string>;

    private readonly addCheckSum?: string;
    private readonly rmCheckSum?: string;
    private readonly port: number;

    private tasksBuffer?: TasksBuffer<{ taskMethod: EMethods; currentIps: Array<Address4 | Address6> }>;
    private server: Express;
    private httpServer?: http.Server;

    static async Initializer(): Promise<App> {
        logger.debug('App.Initializer()');

        if (!process.env.UNIFI_CONTROLLER_URL) {
            throw new Error('please fill process.env.UNIFI_CONTROLLER_URL');
        }
        const controllerUrl = process.env.UNIFI_CONTROLLER_URL;
        if (!process.env.UNIFI_USERNAME) {
            throw new Error('please fill process.env.UNIFI_USERNAME');
        }
        const unifiUsername = process.env.UNIFI_USERNAME;
        if (!process.env.UNIFI_PASSWORD) {
            throw new Error('please fill process.env.UNIFI_PASSWORD');
        }
        const unifiPassword = process.env.UNIFI_PASSWORD;
        const unifiSiteName = process.env.UNIFI_SITE_NAME;

        const controller = new Controller({
            username: unifiUsername,
            password: unifiPassword,
            url: controllerUrl,
            strictSSL: false
        });

        await controller.login();

        const currentSite = await this.getSite(controller, unifiSiteName);

        return new App(currentSite);
    }

    constructor(readonly currentSite: Site) {
        logger.debug('App.construct()');

        //get FWRule / FWGroups
        this.unifiFWGroupNames = (process.env.UNIFI_GROUP_NAME || 'IP_BANNED').replace(/\s+/g, '').split(',');
        this.unifiFWGroupNamesV6 = (process.env.UNIFI_GROUP_NAME_V6 || 'IP_BANNED_V6').replace(/\s+/g, '').split(',');

        this.addCheckSum = process.env.ADD_CHECKSUM;
        this.rmCheckSum = process.env.RM_CHECKSUM || this.addCheckSum;
        const port = Number(process.env.PORT);
        this.port = port || port === 0 ? port : 3000;

        this.tasksBuffer = new TasksBuffer((tasks) => this.handleTasks(tasks));
        this.server = express();
    }

    private getIpObject(ip: string): Address4 | Address6 {
        try {
            //check if it's a valid IPv4
            return new Address4(ip);
        } catch (e) {
            //e is not instance of AddressError
            if ((e as { name: string }).name === 'AddressError') {
                //maybe it's a valid IPv6
                return new Address6(ip);
            } else {
                throw e;
            }
        }
    }

    private taskPromise?: Promise<void>;

    public async start(): Promise<void> {
        logger.debug('App.start()');

        //try to get block group
        const { ipv4, ipv6 } = await this.getFWGroups();

        await this.checkFWGroupsRules([...ipv4, ...ipv6]);

        //start webserver
        this.server.post('/', async (req, res) => {
            try {
                const { token: pToken, ips: pIps } = req.query;
                const token = ((Array.isArray(pToken) ? pToken.shift() : pToken) || '').toString();
                // logger.debug('ask to ban ips');
                if (App.getCheckSum(token) != this.addCheckSum) {
                    logger.debug('token to add ban invalid');
                    return res.status(401).send();
                }

                const ips = (Array.isArray(pIps) ? pIps : [pIps])
                    .filter((i) => !!i)
                    .map((i) => (i || '').toString())
                    .filter((v) => !!v);
                logger.debug('ask to ban ips %s', JSON.stringify(ips));
                this.tasksBuffer?.addTask({
                    taskMethod: EMethods.ADD,
                    currentIps: ips.map((i) => this.getIpObject(i))
                });

                res.status(200).send();
            } catch (e) {
                console.error(e);
                res.status(500).send();
            }
        });

        this.server.delete('/', async (req, res) => {
            try {
                const { token: pToken, ips: pIps } = req.query;
                // logger.debug('ask to unban ips');
                const token = ((Array.isArray(pToken) ? pToken.shift() : pToken) || '').toString();
                if (App.getCheckSum(token) != this.rmCheckSum) {
                    logger.debug('token to remove ban invalid');
                    return res.status(401).send();
                }

                const ips = (Array.isArray(pIps) ? pIps : [pIps]).map((i) => (i || '').toString()).filter((v) => !!v);
                logger.debug('ask to unban ips %s', JSON.stringify(ips));

                this.tasksBuffer?.addTask({
                    taskMethod: EMethods.DEL,
                    currentIps: ips.map((i) => this.getIpObject(i))
                });
                res.status(200).send();
            } catch (e) {
                console.error(e);
                res.status(500).send();
            }
        });

        this.httpServer = this.server.listen(this.port, () => {
            const address = this.httpServer?.address() as AddressInfo;
            logger.info(`Listening at http://localhost:${address.port}`);
        });
    }

    public async kill(): Promise<void> {
        return new Promise((resolve, reject): void => {
            this.server?.removeAllListeners();

            if (this.httpServer) {
                this.httpServer.close((err): void => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve();
                    }
                });
            } else {
                resolve();
            }
        });
    }

    private static getCheckSum(str: string = ''): string {
        return crypto
            .createHash('sha256')
            .update(str || '')
            .digest('hex');
    }

    private async getFWGroups(): Promise<{ ipv4: Array<FWGroup>; ipv6: Array<FWGroup> }> {
        logger.debug('App.getFWGroups()');
        const groups = await this.currentSite?.firewall.getGroups();

        logger.debug('App.getFWGroups() : %d groups loaded', groups?.length);

        const currentGroups = groups
            .filter((r) => r && this.unifiFWGroupNames.includes(r.name))
            .map((g) => {
                g.group_members = g.group_members || [];
                return g;
            });
        if (currentGroups.length !== this.unifiFWGroupNames.length) {
            throw new Error(
                `fail to get group(s) "${this.unifiFWGroupNames.filter((g) => !currentGroups.some((cg) => g === cg.name)).join(', ')}"`
            );
        }

        const currentGroupsV6 = groups
            .filter((r) => r && this.unifiFWGroupNamesV6.includes(r.name))
            .map((g) => {
                g.group_members = g.group_members || [];
                return g;
            });
        if (currentGroupsV6.length !== this.unifiFWGroupNamesV6.length) {
            throw new Error(
                `fail to get group(s) "${this.unifiFWGroupNamesV6.filter((g) => !currentGroupsV6.some((cg) => g === cg.name)).join(', ')}"`
            );
        }

        return { ipv4: currentGroups, ipv6: currentGroupsV6 };
    }

    private _addIps(ip: string, ips: Array<string>): Array<string> {
        if (!ips.includes(ip)) {
            ips.push(ip);
        }

        return ips;
    }

    private _removeIps(ip: string, ips: Array<string>): Array<string> {
        return ips.filter((i) => i != ip);
    }

    private static async getSite(controller: Controller, siteName?: string): Promise<Site> {
        //Get sites
        logger.debug('App.selectSite() : load sites');
        const sites = await controller.getSites();

        logger.debug('App.selectSite() : %d sites loaded', sites.length);

        let site: Site | undefined;
        //search site in settings
        if (siteName) {
            site = sites.find((s) => s.name === siteName);
            if (!site) {
                throw new Error(`fail to get site "${siteName}"`);
            }
        } else {
            if (sites.length === 0) {
                throw new Error('no sites found !');
            }
            site = sites.shift();
        }

        if (!site) {
            throw new Error('fail to get site for an unknown reason');
        }

        logger.debug('App.selectSite() : current site %s', site?.name);
        return site;
    }

    private async handleTasks(tasks: Array<{ taskMethod: EMethods; currentIps: Array<Address4 | Address6> }>): Promise<void> {
        if (this.taskPromise) {
            await this.taskPromise;
        }

        this.taskPromise = new Promise<void>(async (resolve, reject) => {
            try {
                logger.debug('addTask : execute %d tasks', tasks.length);

                const groups = await this.getFWGroups();

                //first flat tasks
                const flatTasks: Array<{ ip: Address4 | Address6; method: EMethods }> = [];
                tasks.forEach((task) => {
                    task.currentIps.forEach((ip) => {
                        flatTasks.push({
                            ip,
                            method: task.taskMethod
                        });
                    });
                });

                let IPv4s = groups.ipv4.map((g) => g.group_members).flat();
                let IPv6s = groups.ipv6.map((g) => g.group_members).flat();
                flatTasks.forEach(({ method, ip }) => {
                    let ipStr: string | undefined;
                    //convert to string + remove useless subnet /32 ( /32 say only one ip )
                    if (ip.subnetMask === 32) {
                        ipStr = ip.addressMinusSuffix;
                    } else {
                        ipStr = ip.address;
                    }

                    if (!ipStr) {
                        //never saw this case
                        logger.error(`Error : fail to get ip from ${ip}`);
                        return;
                    }

                    if (ip instanceof Address4) {
                        IPv4s = method === EMethods.ADD ? this._addIps(ipStr, IPv4s) : this._removeIps(ipStr, IPv4s);
                    } else {
                        IPv6s = method === EMethods.ADD ? this._addIps(ipStr, IPv6s) : this._removeIps(ipStr, IPv6s);
                    }
                });

                //apply first IP banned to all groups, because group need an entry
                groups.ipv4.forEach((g, i) => {
                    const chunk = IPv4s.slice(MAX_IPS_PER_GROUP * i, MAX_IPS_PER_GROUP * (i + 1) - 1);
                    //set the chunk, or the first ip
                    g.group_members = [...new Set(chunk.length > 1 ? chunk : [IPv4s[0]])];
                });

                const ipv4sMissingGroup = IPv4s.length - groups.ipv4.length * MAX_IPS_PER_GROUP - 1;
                if (ipv4sMissingGroup > 0) {
                    logger.warn(`${ipv4sMissingGroup} IPv4 can't be blocked, because no enough groups`);
                }

                //apply first IP banned to all groups, because group need an entry
                groups.ipv6.forEach((g, i) => {
                    const chunk = IPv6s.slice(MAX_IPS_PER_GROUP * i, MAX_IPS_PER_GROUP * (i + 1) - 1);
                    //set the chunk, or the first ip
                    g.group_members = [...new Set(chunk.length > 1 ? chunk : [IPv6s[0]])];
                });
                const ipv6sMissingGroup = IPv6s.length - groups.ipv6.length * MAX_IPS_PER_GROUP - 1;
                if (ipv6sMissingGroup > 0) {
                    logger.warn(`${ipv6sMissingGroup} IPv6 can't be blocked, because no enough groups`);
                }

                [...groups.ipv4, ...groups.ipv6].forEach((g) => {
                    logger.debug('%d members in %s', g.group_members.length, g.name);
                });

                await Promise.all([...groups.ipv4.map((g) => g.save()), ...groups.ipv6.map((g) => g.save())]);
                logger.debug('end tasks');
                resolve();
            } catch (e) {
                reject(e);
            }
        });
    }

    private async checkFWGroupsRules(groups: Array<FWGroup>) {
        logger.debug('App.selectFWRule() : load FW rules');
        const rules = await this.currentSite.firewall.getRules();

        logger.debug('App.selectFWRule() : %d rules loaded', rules.length);

        const unusedGroups = groups.filter(
            (group) => !rules.some((rule) => rule.src_firewallgroup_ids.some((srcGroup) => srcGroup === group._id))
        );
        if (unusedGroups.length) {
            throw new Error(`groups ${unusedGroups.map((g) => g.name).join(', ')} seems not configured`);
        }
    }
}
