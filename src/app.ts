import unifi from 'node-unifi';
import { IFWRule, IGroup, ISite } from './interfaces';
import express from 'express';
import * as crypto from 'crypto';

export default class App {
    private readonly controllerIp: string;
    private readonly controllerPort: number;
    private readonly unifiUsername: string;
    private readonly unifiPassword: string;
    private readonly unifiSiteName: string;
    private readonly unifiFWRuleName: string;
    private readonly unifiFWGroupName: string;

    private currentSite: ISite;
    private currentFWRule: IFWRule;
    private controller: unifi.Controller;
    private addCheckSum: string;
    private rmCheckSum: string;
    private port: number;

    constructor() {
        this.controllerIp = process.env.UNIFI_CONTROLLER_IP;
        this.controllerPort = Number(process.env.UNIFI_CONTROLLER_PORT);
        this.unifiUsername = process.env.UNIFI_USERNAME;
        this.unifiPassword = process.env.UNIFI_PASSWORD;
        this.unifiSiteName = process.env.UNIFI_SITE_NAME;
        this.unifiFWRuleName = process.env.UNIFI_FW_RULE_NAME;
        this.unifiFWGroupName = process.env.UNIFI_GROUP_NAME;

        this.addCheckSum = process.env.ADD_CHECKSUM;
        this.rmCheckSum = process.env.RM_CHECKSUM || this.addCheckSum;
        this.port = Number(process.env.PORT);
    }

    public async start() {
        this.controller = new unifi.Controller(this.controllerIp, this.controllerPort);

        await this.promisify((cb) => {
            this.controller.login(this.unifiUsername, this.unifiPassword, cb);
        });

        //Get sites
        const [tmpSites] = await this.promisify<Array<ISite>>((cb) => {
            this.controller.getSites(cb);
        });

        const sites = Array.isArray(tmpSites) ? tmpSites : [tmpSites];

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

        if (!this.unifiFWRuleName) {
            throw new Error('env.UNIFI_FW_RULE_NAME is mandatory');
        }
        const [[tmpRules]] = await this.promisify<Array<Array<IFWRule>>>((cb) => {
            this.controller.getFirewallRules(this.currentSite.name, cb);
        });
        const rules = Array.isArray(tmpRules) ? tmpRules : [tmpRules];

        this.currentFWRule = rules.find((r) => r.name === this.unifiFWRuleName);
        if (!this.currentFWRule) {
            throw new Error(`fail to get rule "${this.unifiFWRuleName}"`);
        }

        //try to get block group
        await this.getBlockGroup();

        //start webserver
        const app = express();
        app.post('/', async (req, res, next) => {
            try {
                const { token: pToken, ips: pIps } = req.query;
                const token = (Array.isArray(pToken) ? pToken.shift() : pToken).toString();
                if (App.getCheckSum(token) != this.addCheckSum) {
                    return res.status(401).send();
                }

                const ips = (Array.isArray(pIps) ? pIps : [pIps]).map((i) => i.toString());

                await this.addIps(ips);
                res.status(200).send();
            } catch (e) {
                console.error(e);
                res.status(500).send();
            }
        });

        app.delete('/', async (req, res, next) => {
            try {
                const { token: pToken, ips: pIps } = req.query;
                const token = (Array.isArray(pToken) ? pToken.shift() : pToken).toString();
                if (App.getCheckSum(token) != this.rmCheckSum) {
                    return res.status(401).send();
                }

                const ips = (Array.isArray(pIps) ? pIps : [pIps]).map((i) => i.toString());

                await this.removeIps(ips);
                res.status(200).send();
            } catch (e) {
                console.error(e);
                res.status(500).send();
            }
        });

        app.listen(this.port, () => {
            console.log(`Listening at http://localhost:${this.port}`);
        });
    }

    private static getCheckSum(str: string = ''): string {
        return crypto
            .createHash('sha256')
            .update(str || '')
            .digest('hex');
    }

    private async getBlockGroup(): Promise<IGroup> {
        const [[tmpGroups]] = await this.promisify<Array<Array<IGroup>>>((cb) => {
            this.controller.getFirewallGroups(this.currentSite.name, cb);
        });
        const groups = Array.isArray(tmpGroups) ? tmpGroups : [tmpGroups];

        const currentGroup = groups.find((r) => r.name === this.unifiFWGroupName);
        if (!currentGroup) {
            throw new Error(`fail to get group "${this.unifiFWGroupName}"`);
        }

        //just to secure
        currentGroup.group_members = currentGroup.group_members || [];

        return currentGroup;
    }

    public async updateGroup(group: IGroup) {
        const [[ret]] = await this.promisify<Array<Array<IGroup>>>((cb) => {
            this.controller.editFirewallGroup(
                this.currentSite.name,
                group._id,
                group.site_id,
                group.name,
                group.group_type,
                cb,
                group.group_members
            );
        });
        return ret;
    }

    public async addIps(ips: Array<string>) {
        //get group to update it
        const group = await this.getBlockGroup();
        ips.forEach((addIp) => {
            if (!group.group_members.includes(addIp)) {
                group.group_members.push(addIp);
            }
        });

        await this.updateGroup(group);
    }

    public async removeIps(ips: Array<string>) {
        //get group to update it
        const group = await this.getBlockGroup();
        ips.forEach((delIp) => {
            group.group_members = group.group_members.filter((ip) => ip != delIp);
        });

        await this.updateGroup(group);
    }

    private async promisify<T>(fn: (cb) => void): Promise<Array<T> | T> {
        return new Promise((resolve, reject) => {
            fn((err, ...args) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(args);
                }
            });
        });
    }
}
