//import global first, to set env
import './global';
import App from './app';

try {
    App.Initializer()
        .then((app) => app.start())
        .catch((e) => console.error(e));
} catch (e) {
    console.error(e);
    throw e;
}

process.on('unhandledRejection', (reason, p) => {
    console.log('Unhandled Rejection at: Promise', p, 'reason:', reason);
    // application specific logging, throwing an error, or other logic here
});
