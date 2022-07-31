export class CustomError extends Error {
  public readonly privateMessage: string;

  public constructor(str: string, privateMessage = '') {
    super(str);
    this.privateMessage = privateMessage || str;
  }
}
