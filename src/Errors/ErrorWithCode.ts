import { CustomError } from './CustomError';

export class ErrorWithCode extends CustomError {
  public readonly code: number;

  public readonly privateMessage: string;

  public constructor(str: string, code = 500, privateMessage = '') {
    super(str);
    this.code = code;
    this.privateMessage = privateMessage || str;
  }
}
