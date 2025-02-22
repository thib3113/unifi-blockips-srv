import winston from 'winston';
// @ts-ignore
import type { TransformableInfo } from 'logform';

function logFormatter(info: TransformableInfo): string {
    const elements: Array<string> = [];

    if (info.timestamp) {
        elements.push(`[${info.timestamp}]`);
    }

    let message = info.message;
    if (message && typeof (message as unknown) != 'string') {
        try {
            message = JSON.stringify(message);
        } catch (e) {
            message = `<unStringifiable ${typeof message}> ${message}`;
        }
    }

    elements.push(info.level || 'unknown');
    elements.push(info.stack ? info.stack : message);
    return elements.join(' ');
}

const logLevels = ['error', 'warn', 'info', 'http', 'verbose', 'debug', 'silly'];

const tmpLogLevel = process.env.LOG_LEVEL;

let logLevel = 'info';
if (tmpLogLevel && logLevels.includes(tmpLogLevel.toLowerCase())) {
    logLevel = tmpLogLevel;
}

console.log(`set logLevel to : ${logLevel}`);

export const logger = winston.createLogger({
    level: logLevel,
    format: winston.format.json(),
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.timestamp({
                    format: 'YYYY-MM-DD HH:mm:ss.SSS ZZ'
                }),
                winston.format.colorize(),
                winston.format.splat(),
                winston.format.simple(),
                winston.format.printf((info: TransformableInfo): string => logFormatter(info))
            ),
            handleExceptions: true
        })
    ]
});

export default logger;
