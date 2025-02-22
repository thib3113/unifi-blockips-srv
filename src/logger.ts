import winston from 'winston';
import type { TransformableInfo } from 'logform';

function logFormatter(info: TransformableInfo): string {
    const elements: Array<string> = [];

    if (info.timestamp) {
        elements.push(`[${info.timestamp}]`);
    }

    let message = info.message;
    let strMessage = '';
    if (message) {
        if (typeof message === 'string') {
            strMessage = message;
        } else {
            try {
                strMessage = JSON.stringify(message);
            } catch (e) {
                strMessage = `<unStringifiable ${typeof message}> ${message}`;
            }
        }
    }

    elements.push(info.level || 'unknown');
    elements.push(info.stack ? info.stack.toString() : strMessage);
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
