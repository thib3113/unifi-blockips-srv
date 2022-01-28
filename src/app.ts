import Controller, { FWGroup, FWRule, Site } from 'unifi-client';
import express, { Express } from 'express';
import * as crypto from 'crypto';
import createDebug from 'debug';
import { TasksBuffer } from './TasksBuffer';
import * as http from 'http';
import { Address4, Address6 } from 'ip-address';
import { AddressInfo } from 'net';

const enum EMethods {
    ADD,
    DEL
}

const debug = createDebug('unifi-blockips-srv');
export default class App {
    private readonly unifiUsername: string;
    private readonly unifiPassword: string;
    private readonly unifiSiteName: string;
    private readonly unifiFWRuleName: string;
    private readonly unifiFWGroupName: string;
    private readonly unifiFWRuleNameV6: string;
    private readonly unifiFWGroupNameV6: string;

    private currentSite: Site;
    private currentFWRule: FWRule;
    private currentFWRuleV6: FWRule;
    private readonly addCheckSum: string;
    private readonly rmCheckSum: string;
    private readonly port: number;

    private readonly controllerUrl: string;
    private controller: Controller;
    private tasksBuffer: TasksBuffer<{ taskMethod: EMethods; currentIps: Array<Address4 | Address6> }>;
    private server: Express;
    private httpServer: http.Server;

    constructor() {
        debug('App.construct()');
        if (!process.env.UNIFI_CONTROLLER_URL) {
            throw new Error('please fill process.env.UNIFI_CONTROLLER_URL');
        }
        this.controllerUrl = process.env.UNIFI_CONTROLLER_URL;
        if (!process.env.UNIFI_USERNAME) {
            throw new Error('please fill process.env.UNIFI_USERNAME');
        }
        this.unifiUsername = process.env.UNIFI_USERNAME;
        if (!process.env.UNIFI_PASSWORD) {
            throw new Error('please fill process.env.UNIFI_PASSWORD');
        }
        this.unifiPassword = process.env.UNIFI_PASSWORD;
        this.unifiSiteName = process.env.UNIFI_SITE_NAME;

        //get FWRule / FWGroups
        this.unifiFWRuleName = process.env.UNIFI_FW_RULE_NAME || 'Banned IPs';
        this.unifiFWGroupName = process.env.UNIFI_GROUP_NAME || 'IP_BANNED';
        this.unifiFWRuleNameV6 = process.env.UNIFI_FW_RULE_NAME_V6 || 'Banned IPV6s';
        this.unifiFWGroupNameV6 = process.env.UNIFI_GROUP_NAME_V6 || 'IP_BANNED_V6';

        this.addCheckSum = process.env.ADD_CHECKSUM;
        this.rmCheckSum = process.env.RM_CHECKSUM || this.addCheckSum;
        const port = Number(process.env.PORT);
        this.port = port || port === 0 ? port : 3000;
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

    private taskPromise: Promise<void> = null;

    public async start(): Promise<void> {
        debug('App.start()');

        this.controller = new Controller({
            username: this.unifiUsername,
            password: this.unifiPassword,
            url: this.controllerUrl,
            strictSSL: false
        });

        await this.controller.login();

        await this.selectSite();

        await this.selectFWRule();

        //try to get block group
        await this.getFWGroups();

        this.tasksBuffer = new TasksBuffer((tasks) => this.handleTasks(tasks));

        //start webserver
        this.server = express();
        this.server.post('/', async (req, res) => {
            try {
                const { token: pToken, ips: pIps } = req.query;
                const token = (Array.isArray(pToken) ? pToken.shift() : pToken).toString();
                // debug('ask to ban ips');
                if (App.getCheckSum(token) != this.addCheckSum) {
                    debug('token to add ban invalid');
                    return res.status(401).send();
                }

                const ips = (Array.isArray(pIps) ? pIps : [pIps]).filter((i) => !!i).map((i) => i.toString());
                debug('ask to ban ips %s', JSON.stringify(ips));
                this.tasksBuffer.addTask({
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
                // debug('ask to unban ips');
                const token = (Array.isArray(pToken) ? pToken.shift() : pToken).toString();
                if (App.getCheckSum(token) != this.rmCheckSum) {
                    debug('token to remove ban invalid');
                    return res.status(401).send();
                }

                const ips = (Array.isArray(pIps) ? pIps : [pIps]).map((i) => i.toString());
                debug('ask to unban ips %s', JSON.stringify(ips));

                this.tasksBuffer.addTask({
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
            const address = this.httpServer.address() as AddressInfo;
            console.log(`Listening at http://localhost:${address.port}`);
        });
    }

    public async kill(): Promise<void> {
        return new Promise((resolve, reject): void => {
            this.server.removeAllListeners();
            this.server = null;
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

    private async getFWGroups(): Promise<{ ipv4: FWGroup; ipv6?: FWGroup }> {
        debug('App.getFWGroups()');
        const groups = await this.currentSite.firewall.getGroups();

        debug('App.getFWGroups() : %d groups loaded', groups.length);

        const currentGroup = groups.find((r) => r && r.name === this.unifiFWGroupName);
        if (!currentGroup) {
            throw new Error(`fail to get group "${this.unifiFWGroupName}"`);
        }

        const currentGroupV6 = groups.find((r) => r && r.name === this.unifiFWGroupNameV6);
        if (!currentGroupV6) {
            throw new Error(`fail to get group "${this.unifiFWGroupNameV6}"`);
        }

        //just to secure
        currentGroup.group_members = currentGroup.group_members || [];
        currentGroupV6.group_members = currentGroupV6.group_members || [];

        return { ipv4: currentGroup, ipv6: currentGroupV6 };
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

    private async selectSite(): Promise<void> {
        //Get sites
        debug('App.selectSite() : load sites');
        const sites = await this.controller.getSites();

        debug('App.selectSite() : %d sites loaded', sites.length);

        //search site in settings
        if (this.unifiSiteName) {
            this.currentSite = sites.find((s) => s.name === this.unifiSiteName);
            if (!this.currentSite) {
                throw new Error(`fail to get site "${this.unifiSiteName}"`);
            }
        } else {
            if (sites.length === 0) {
                throw new Error('no sites found !');
            }
            this.currentSite = sites.shift();
        }
        debug('App.selectSite() : current site %s', this.currentSite?.name);
    }

    private async selectFWRule(): Promise<void> {
        if (!this.unifiFWRuleName || !this.unifiFWRuleNameV6) {
            throw new Error('env.UNIFI_FW_RULE_NAME and env.UNIFI_FW_RULE_NAME_V6 are mandatory');
        }
        debug('App.selectFWRule() : load FW rules');
        const rules = await this.currentSite.firewall.getRules();

        debug('App.selectFWRule() : %d rules loaded', rules.length);

        this.currentFWRule = rules.find((r) => r.name === this.unifiFWRuleName);
        if (!this.currentFWRule) {
            throw new Error(`fail to get rule "${this.unifiFWRuleName}"`);
        }

        this.currentFWRuleV6 = rules.find((r) => r.name === this.unifiFWRuleNameV6);
        if (!this.currentFWRuleV6) {
            throw new Error(`fail to get rule "${this.unifiFWRuleNameV6}"`);
        }
    }

    private async handleTasks(tasks: Array<{ taskMethod: EMethods; currentIps: Array<Address4 | Address6> }>): Promise<void> {
        if (this.taskPromise) {
            await this.taskPromise;
        }

        this.taskPromise = new Promise<void>(async (resolve, reject) => {
            try {
                debug('addTask : execute %d tasks', tasks.length);

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

                let IPv4s = groups.ipv4.group_members;
                let IPv6s = groups.ipv6.group_members;
                flatTasks.forEach(({ method, ip }) => {
                    let ipStr;
                    //convert to string + remove useless subnet /32 ( /32 say only one ip )
                    if (ip.subnetMask === 32) {
                        ipStr = ip.addressMinusSuffix;
                    } else {
                        ipStr = ip.address;
                    }
                    if (ip instanceof Address4) {
                        IPv4s = method === EMethods.ADD ? this._addIps(ipStr, IPv4s) : this._removeIps(ipStr, IPv4s);
                    } else {
                        IPv6s = method === EMethods.ADD ? this._addIps(ipStr, IPv6s) : this._removeIps(ipStr, IPv6s);
                    }
                });

                groups.ipv4.group_members = IPv4s;
                groups.ipv6.group_members = IPv6s;
                return Promise.all([groups.ipv4.save(), groups.ipv6.save()]);

                resolve();
            } catch (e) {
                reject(e);
            }
        });
    }
}
