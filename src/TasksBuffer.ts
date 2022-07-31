export class TasksBuffer<T> {
    private tasks: Array<T> = [];
    private timeout?: NodeJS.Timeout;
    private maxTimeout?: NodeJS.Timeout;
    constructor(
        readonly callBackFunction: (tasks: Array<T>) => Promise<void>,
        readonly timer: number = 5000,
        readonly maxTimer: number = 5 * 60 * 1000
    ) {}

    public addTask(task: T): void {
        if (!this.tasks) {
            this.tasks = [];
        }
        this.tasks.push(task);
        this.startTimer();
    }

    public async flush(): Promise<void> {
        this.clearTimeout();
        this.clearMaxTimeout();

        const tasks = this.tasks.slice(0);
        this.tasks = [];
        await this.callBackFunction(tasks);
    }

    private clearTimeout(): void {
        if (this.timeout) {
            clearTimeout(this.timeout);
            delete this.timeout;
        }
    }

    private clearMaxTimeout(): void {
        if (this.maxTimeout) {
            clearTimeout(this.maxTimeout);
            delete this.maxTimeout;
        }
    }

    private startTimer() {
        this.clearTimeout();

        this.timeout = setTimeout(() => this.flush(), this.timer);
        if (!this.maxTimeout) {
            this.maxTimeout = setTimeout(() => this.flush(), this.maxTimer);
        }
    }
}
