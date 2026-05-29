//import global first, to set env
import './global';
import App from './app';
import logger from './logger';

try {
    App.Initializer()
        .then((app) => app.start())
        .catch((e) => logger.error('Error starting app', e));
} catch (e) {
    logger.error('Uncaught exception', e);
    throw e;
}

process.on('unhandledRejection', (reason, p) => {
    logger.error(`Unhandled Rejection at: Promise ${p} reason: ${reason}`);
    // application specific logging, throwing an error, or other logic here
});
