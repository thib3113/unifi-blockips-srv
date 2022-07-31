import { ErrorWithCode } from './ErrorWithCode';

export class UnAuthorizedError extends ErrorWithCode {
    public constructor(str = '', privateMessage = '') {
        super(`Unauthorized${str ? ` ${str}` : ''}`, 401, privateMessage);
    }
}
