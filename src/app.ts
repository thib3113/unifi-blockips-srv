import Controller, { Site } from 'unifi-client';
import express, { Express, Request } from 'express';
import * as crypto from 'crypto';
import * as http from 'http';
import { AddressInfo } from 'net';
import logger from './logger';
import { Blocker } from './Blocker';
import { UnAuthorizedError } from './Errors/UnAuthorizedError';
import { ErrorWithCode } from './Errors/ErrorWithCode';
import { BouncerClient } from 'crowdsec-client';
import fs from 'fs';

export default class App {
    private readonly unifiFWGroupNames: Array<string>;
    private readonly unifiFWGroupNamesV6: Array<string>;

    private readonly addCheckSum?: string;
    private readonly rmCheckSum?: string;
    private readonly port: number;

    private readonly server: Express;
    private httpServer?: http.Server;
    private readonly blocker: Blocker;
    private readonly crowdsecClient?: BouncerClient;

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
        this.unifiFWGroupNames = (process.env.UNIFI_GROUP_NAME ?? 'IP_BANNED').replace(/\s+/g, '').split(',');
        this.unifiFWGroupNamesV6 = (process.env.UNIFI_GROUP_NAME_V6 ?? 'IP_BANNED_V6').replace(/\s+/g, '').split(',');

        this.addCheckSum = process.env.ADD_CHECKSUM;
        this.rmCheckSum = process.env.RM_CHECKSUM ?? this.addCheckSum;
        const port = Number(process.env.PORT);
        this.port = port || port === 0 ? port : 3000;

        this.blocker = new Blocker(this.currentSite);

        this.server = express();

        const {
            CROWDSEC_URL,
            CROWDSEC_API_KEY,
            CROWDSEC_DISABLE_SSL_CHECK,
            CROWDSEC_CLIENT_CERT,
            CROWDSEC_CLIENT_KEY,
            CROWDSEC_CLIENT_CA
        } = process.env;

        const certAuthentication = CROWDSEC_CLIENT_CERT && CROWDSEC_CLIENT_KEY && CROWDSEC_CLIENT_CA;
        if (CROWDSEC_URL && (CROWDSEC_API_KEY || certAuthentication)) {
            if (!certAuthentication) {
                this.crowdsecClient = new BouncerClient({
                    timeout: 10000,
                    url: CROWDSEC_URL,
                    auth: {
                        apiKey: CROWDSEC_API_KEY ?? ''
                    },
                    strictSSL: !CROWDSEC_DISABLE_SSL_CHECK,
                    userAgent: 'unifi-blockips/1.6.0'
                });
            } else {
                const [cert, key, ca] = [CROWDSEC_CLIENT_CERT, CROWDSEC_CLIENT_KEY, CROWDSEC_CLIENT_CA].map((file) => {
                    try {
                        return fs.readFileSync(file);
                    } catch (e) {
                        throw new Error(`fail to read file: ${file} : ${e}`);
                    }
                });

                this.crowdsecClient = new BouncerClient({
                    timeout: 10000,
                    url: CROWDSEC_URL,
                    auth: {
                        cert,
                        key,
                        ca
                    },
                    strictSSL: !CROWDSEC_DISABLE_SSL_CHECK
                });
            }
        }
    }

    private validateToken(req: Request, tokenBase: string = '') {
        const { token: pToken } = req.query;
        const token = ((Array.isArray(pToken) ? pToken.shift() : pToken) || '').toString();
        if (tokenBase && App.getCheckSum(token) != tokenBase) {
            logger.debug('token to add ban invalid');
            throw new UnAuthorizedError();
        }
    }

    private validateTokenAndGetIps(tokenBase: string = '', req: Request): Array<string> {
        const { ips: pIps } = req.query;

        this.validateToken(req, tokenBase);

        return (Array.isArray(pIps) ? pIps : [pIps])
            .filter((i) => !!i)
            .map((i) => (i || '').toString())
            .filter((v) => !!v);
    }

    private async flush() {
        await Promise.all([Blocker.blockers.ipv4?.flush(), Blocker.blockers.ipv6?.flush()]);
    }

    public async start(): Promise<void> {
        logger.debug('App.start()');

        await this.blocker.start([...this.unifiFWGroupNames, ...this.unifiFWGroupNamesV6]);

        if (this.crowdsecClient) {
            await this.crowdsecClient.login();

            await this.flush();

            const stream = this.crowdsecClient.Decisions.getStream({
                scopes: 'ip'
            });
            stream.on('added', (decision) => {
                this.blocker.ban([decision.value]);
            });
            stream.on('deleted', (decision) => {
                this.blocker.unban([decision.value]);
            });

            stream.start();
        }

        //start webserver
        this.server.post('/', async (req, res) => {
            try {
                const ips = this.validateTokenAndGetIps(this.addCheckSum, req);
                logger.debug('ask to ban ips %s', JSON.stringify(ips));

                this.blocker.ban(ips);

                res.status(200).send();
            } catch (e) {
                if (e instanceof ErrorWithCode) {
                    res.status(e.code).send(e.message);
                    return;
                }
                console.error(e);
                res.status(500).send();
            }
        });

        this.server.post('/flush', async (req, res) => {
            try {
                this.validateToken(req, this.addCheckSum);
                logger.debug('ask to flush');

                await this.flush();

                res.status(200).send();
            } catch (e) {
                if (e instanceof ErrorWithCode) {
                    res.status(e.code).send(e.message);
                    return;
                }
                console.error(e);
                res.status(500).send();
            }
        });

        this.server.delete('/', async (req, res) => {
            try {
                const ips = this.validateTokenAndGetIps(this.rmCheckSum, req);
                logger.debug('ask to unban ips %s', JSON.stringify(ips));

                this.blocker.unban(ips);

                res.status(200).send();
            } catch (e) {
                if (e instanceof ErrorWithCode) {
                    res.status(e.code).send(e.message);
                    return;
                }
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
}
