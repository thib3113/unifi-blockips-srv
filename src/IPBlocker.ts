import { FWGroup, Site } from 'unifi-client';
import { Address4, Address6 } from 'ip-address';
import logger from './logger';
import { TasksBuffer } from './TasksBuffer';

const MAX_IPS_PER_GROUP = 10000;

const enum EMethods {
    ADD,
    DEL
}

interface ITask<T> {
    method: EMethods;
    ip: T;
}

export class IPBlocker<T extends Address4 | Address6> {
    private tasksBuffer: TasksBuffer<ITask<T>>;
    private groups: Array<FWGroup> = [];
    private taskPromise?: Promise<void>;

    constructor(readonly currentSite: Site) {
        this.tasksBuffer = new TasksBuffer((tasks) => this.handleTasks(tasks));
    }

    private async handleTasks(tasks: Array<ITask<T>>): Promise<void> {
        if (this.groups.length === 0) {
            throw new Error('not initialized');
        }

        if (this.taskPromise) {
            await this.taskPromise;
        }

        this.taskPromise = new Promise<void>(async (resolve, reject) => {
            try {
                // get name from group
                const blockerName = `${this.groups[0].group_type === 'address-group' ? 'ipv4' : 'ipv6'}-blocker`;

                logger.debug(`${blockerName} addTask : execute %d tasks`, tasks.length);

                const groups = await this.getFWGroups();

                let IPs = groups.map((g) => g.group_members).flat();
                tasks.forEach(({ method, ip }) => {
                    let ipStr: string | undefined;
                    //convert to string + remove useless subnet /32 ( /32 say only one ip )
                    if (ip.subnetMask === 32) {
                        ipStr = ip.addressMinusSuffix;
                    } else {
                        ipStr = ip.address;
                    }

                    if (!ipStr) {
                        //never saw this case
                        logger.error(`${blockerName} : fail to get ip from ${ip}`);
                        return;
                    }

                    IPs = method === EMethods.ADD ? this._addIps(ipStr, IPs) : this._removeIps(ipStr, IPs);
                });

                //apply first IP banned to all groups, because group need an entry
                groups.forEach((g, i) => {
                    const chunk = IPs.slice(MAX_IPS_PER_GROUP * i, MAX_IPS_PER_GROUP * (i + 1) - 1);
                    //set the chunk, or the first ip
                    g.group_members = [...new Set(chunk.length > 1 ? chunk : [IPs[0]])];
                });

                const IPsMissingGroup = IPs.length - groups.length * MAX_IPS_PER_GROUP - 1;
                if (IPsMissingGroup > 0) {
                    logger.warn(`${blockerName} : ${IPsMissingGroup} IPs can't be blocked, because no enough groups`);
                }

                groups.forEach((g) => {
                    logger.debug(`${blockerName} : %d members in %s`, g.group_members.length, g.name);
                });

                await Promise.all(groups.map((g) => g.save()));
                logger.debug(`${blockerName} : end tasks`);
                resolve();
            } catch (e) {
                reject(e);
            }
        });
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

    public ban(ip: T) {
        this.tasksBuffer.addTask({
            method: EMethods.ADD,
            ip
        });
    }

    public unban(ip: T) {
        this.tasksBuffer.addTask({
            method: EMethods.DEL,
            ip
        });
    }

    addGroup(group: FWGroup) {
        this.groups.push(group);
    }

    private async getFWGroups(): Promise<Array<FWGroup>> {
        const groups = await this.currentSite.firewall.getGroups();

        return groups.filter((fwGroup) => this.groups.some((g) => g._id === fwGroup._id));
    }
}
