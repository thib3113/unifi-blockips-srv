import Controller, { FWGroup, FWRule, Site } from 'unifi-client';
import express, { Express } from 'express';
import * as crypto from 'crypto';
import createDebug from 'debug';
import { TasksBuffer } from './TasksBuffer';
import * as http from 'http';

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

    private currentSite: Site;
    private currentFWRule: FWRule;
    private readonly addCheckSum: string;
    private readonly rmCheckSum: string;
    private readonly port: number;

    private readonly controllerUrl: string;
    private controller: Controller;
    private tasksBuffer: TasksBuffer<{ taskMethod: EMethods; currentIps: Array<string> }>;
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
        this.unifiFWRuleName = process.env.UNIFI_FW_RULE_NAME;
        this.unifiFWGroupName = process.env.UNIFI_GROUP_NAME;

        this.addCheckSum = process.env.ADD_CHECKSUM;
        this.rmCheckSum = process.env.RM_CHECKSUM || this.addCheckSum;
        this.port = Number(process.env.PORT) ?? 3000;
    }

    private sanitizeIp(ip: string): string {
        // ip/32 === ip
        return ip.replace('/32', '');
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
        await this.getBlockGroup();

        this.tasksBuffer = new TasksBuffer((tasks) => this.handleTasks(tasks));

        //start webserver
        this.server = express();
        this.server.post('/', async (req, res) => {
            try {
                const { token: pToken, ips: pIps } = req.query;
                const token = (Array.isArray(pToken) ? pToken.shift() : pToken).toString();
                debug('ask to ban ips');
                if (App.getCheckSum(token) != this.addCheckSum) {
                    debug('token to add ban invalid');
                    return res.status(401).send();
                }

                const ips = (Array.isArray(pIps) ? pIps : [pIps]).map((i) => i.toString());
                debug('ask to ban ips %s', JSON.stringify(ips));
                this.tasksBuffer.addTask({
                    taskMethod: EMethods.ADD,
                    currentIps: ips.map((i) => this.sanitizeIp(i))
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
                debug('ask to unban ips');
                const token = (Array.isArray(pToken) ? pToken.shift() : pToken).toString();
                if (App.getCheckSum(token) != this.rmCheckSum) {
                    debug('token to remove ban invalid');
                    return res.status(401).send();
                }

                const ips = (Array.isArray(pIps) ? pIps : [pIps]).map((i) => i.toString());
                debug('ask to unban ips %s', JSON.stringify(ips));

                this.tasksBuffer.addTask({
                    taskMethod: EMethods.DEL,
                    currentIps: ips.map((i) => this.sanitizeIp(i))
                });
                // await this.removeIps(ips);
                res.status(200).send();
            } catch (e) {
                console.error(e);
                res.status(500).send();
            }
        });

        this.httpServer = this.server.listen(this.port, () => {
            console.log(`Listening at http://localhost:${this.port}`);
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

    private async getBlockGroup(): Promise<FWGroup> {
        debug('App.getBlockGroup()');
        const groups = await this.currentSite.firewall.getGroups();

        debug('App.getBlockGroup() : %d groups loaded', groups.length);

        const currentGroup = groups.find((r) => r && r.name === this.unifiFWGroupName);
        if (!currentGroup) {
            throw new Error(`fail to get group "${this.unifiFWGroupName}"`);
        }

        //just to secure
        currentGroup.group_members = currentGroup.group_members || [];

        return currentGroup;
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
        if (!this.unifiFWRuleName) {
            throw new Error('env.UNIFI_FW_RULE_NAME is mandatory');
        }
        debug('App.selectFWRule() : load FW rules');
        const rules = await this.currentSite.firewall.getRules();

        debug('App.selectFWRule() : %d rules loaded', rules.length);

        this.currentFWRule = rules.find((r) => r.name === this.unifiFWRuleName);
        if (!this.currentFWRule) {
            throw new Error(`fail to get rule "${this.unifiFWRuleName}"`);
        }
    }

    private async handleTasks(tasks: Array<{ taskMethod: EMethods; currentIps: Array<string> }>): Promise<void> {
        if (this.taskPromise) {
            await this.taskPromise;
        }

        this.taskPromise = new Promise<void>(async (resolve, reject) => {
            try {
                debug('addTask : execute %d tasks', tasks.length);

                const group = await this.getBlockGroup();

                //first flat tasks
                const flatTasks: Array<{ ip: string; method: EMethods }> = [];
                tasks.forEach((task) => {
                    task.currentIps.forEach((ip) => {
                        flatTasks.push({
                            ip,
                            method: task.taskMethod
                        });
                    });
                });

                let ips = group.group_members;
                flatTasks.forEach(({ method, ip }) => {
                    ips = method === EMethods.ADD ? this._addIps(ip, ips) : this._removeIps(ip, ips);
                });

                group.group_members = ips;
                await group.save();
                resolve();
            } catch (e) {
                reject(e);
            }
        });
    }
}
