import { LogService } from "./LogService";
export interface Context {
  readonly logger: LogService;
  readonly hostWithProtocol: string;
}
