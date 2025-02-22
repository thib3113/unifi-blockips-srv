import { IPBlocker } from './IPBlocker';
import { FWGroup, Site, timestampDate } from 'unifi-client';
import logger from './logger';
import { Address4, Address6 } from 'ip-address';
import type { FirewallPolicy } from './firewallPolicy';

type ipBlocker<T extends Address4 | Address6> = T extends Address4 ? IPBlocker<T> : T extends Address6 ? IPBlocker<T> : never;

export class Blocker {
    static readonly blockers: { ipv4?: IPBlocker<Address4>; ipv6?: IPBlocker<Address6> } = {};
    private useZoneFirewall: boolean = false;

    constructor(readonly currentSite: Site) {}

    private async checkIfUseZoneFirewall(): Promise<void> {
        try {
            this.useZoneFirewall = (
                await this.currentSite
                    .getInstance()
                    .get<
                        Array<{ _id: string; timestamp: timestampDate; feature: 'ZONE_BASED_FIREWALL' | string }>
                    >('/site-feature-migration', {
                        apiVersion: 2
                    })
            ).data.some((migration) => migration.feature === 'ZONE_BASED_FIREWALL');
        } catch (e) {
            logger.error(`fail to check feature migration : %o`, e);
            this.useZoneFirewall = false;
        }
    }

    public async start(unifiFWGroupNames: Array<string>) {
        await this.checkIfUseZoneFirewall();
        await this.prepareBlockers(unifiFWGroupNames);
    }

    private async checkFWGroupsRules(groups: Array<FWGroup>) {
        logger.debug('Blocker.selectFWRule() : load FW rules');

        if (this.useZoneFirewall) {
            const externalZone = await (async (): Promise<string> => {
                let zone: { _id: string; zone_key: string } | undefined;
                try {
                    zone = (
                        await this.currentSite.getInstance().get<Array<{ _id: string; zone_key: string }>>('/firewall/zone', {
                            apiVersion: 2,
                            apiPart: true
                        })
                    ).data.find((z) => z.zone_key === 'external');
                } catch (e) {
                    logger.error(`fail to get external zone: %o`, e);
                    throw new Error('fail to get external zone');
                }
                if (!zone?._id) {
                    throw new Error('fail to get external zone');
                }

                return zone._id;
            })();
            const policies = (
                await this.currentSite.getInstance().get<Array<FirewallPolicy>>('/firewall-policies', {
                    apiVersion: 2,
                    apiPart: true
                })
            ).data;
            logger.debug('Blocker.selectFWRule() : %d policies loaded', policies.length);
            const unusedGroups = groups.filter(
                (group) =>
                    !policies.some(
                        (policy) =>
                            policy.source.zone_id === externalZone &&
                            ['REJECT', 'BLOCK'].includes(policy.action) &&
                            policy.source.ip_group_id === group._id
                    )
            );
            if (unusedGroups.length) {
                throw new Error(`groups ${unusedGroups.map((g) => g.name).join(', ')} seems not configured`);
            }
        } else {
            const rules = await this.currentSite.firewall.getRules();
            logger.debug('Blocker.selectFWRule() : %d rules loaded', rules.length);
            const unusedGroups = groups.filter(
                (group) => !rules.some((rule) => rule.src_firewallgroup_ids.some((srcGroup) => srcGroup === group._id))
            );
            if (unusedGroups.length) {
                throw new Error(`groups ${unusedGroups.map((g) => g.name).join(', ')} seems not configured`);
            }
        }
    }

    async prepareBlockers(unifiFWGroupNames: Array<string>): Promise<void> {
        logger.debug('Blocker.prepareBlockers()');
        const groups = await this.currentSite.firewall.getGroups();

        logger.debug('Blocker.prepareBlockers() : %d groups loaded', groups?.length);

        const currentGroups = groups
            .filter((r) => r && unifiFWGroupNames.includes(r.name))
            .map((g) => {
                g.group_members = g.group_members || [];
                return g;
            });
        if (currentGroups.length !== unifiFWGroupNames.length) {
            throw new Error(
                `fail to get group(s) "${unifiFWGroupNames.filter((g) => !currentGroups.some((cg) => g === cg.name)).join(', ')}"`
            );
        }

        await this.checkFWGroupsRules(currentGroups);

        currentGroups.forEach((g) => {
            let blocker: IPBlocker<Address4> | IPBlocker<Address6>;
            switch (g.group_type) {
                case 'address-group':
                    blocker = Blocker.blockers.ipv4 = Blocker.blockers.ipv4 ?? new IPBlocker<Address4>(this.currentSite);
                    break;
                case 'ipv6-address-group':
                    blocker = Blocker.blockers.ipv6 = Blocker.blockers.ipv6 ?? new IPBlocker<Address6>(this.currentSite);
                    break;
                default:
                    throw new Error(`not supported group type "${g.group_type}"`);
            }

            blocker.addGroup(g);
        });
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

    private getBlocker(ip: Address4 | Address6): undefined | ipBlocker<typeof ip> {
        if (ip instanceof Address6) {
            if (!Blocker.blockers.ipv6) {
                logger.warn(`Blocker.getBlocker() : no ipv6 blocker found can't block ip ${ip.address}`);
                return;
            }
            return Blocker.blockers.ipv6;
        } else {
            if (!Blocker.blockers.ipv4) {
                logger.warn(`Blocker.getBlocker() : no ipv4 blocker found can't block ip ${ip.address}`);
                return;
            }

            return Blocker.blockers.ipv4;
        }
    }

    public ban(ips: Array<string>) {
        //as any, because blocker return come from the type of the ip
        ips.map((ip) => this.getIpObject(ip)).forEach((ip) => this.getBlocker(ip)?.ban(ip as any));
    }

    public unban(ips: Array<string>) {
        //as any, because blocker return come from the type of the ip
        ips.map((ip) => this.getIpObject(ip)).forEach((ip) => this.getBlocker(ip)?.unban(ip as any));
    }
}
