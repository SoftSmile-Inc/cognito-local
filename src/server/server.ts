import cors from "cors";
import express from "express";
import { engine } from "express-handlebars";
import * as http from "http";
import type { Logger } from "pino";
import * as uuid from "uuid";
import { CognitoError, UnsupportedError } from "../errors";
import { Router } from "./Router";
import PublicKey from "../keys/cognitoLocal.public.json";
import Pino from "pino-http";
import path from "path";
import { TokenRequestHandle } from "../targets/oauth2/tokenTarget";

export interface ServerOptions {
  port: number;
  hostname: string;
  development: boolean;
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
class Oauth2Error {
  static invalid_request: Oauth2Error = new Oauth2Error("invalid_request");
  static invalid_client: Oauth2Error = new Oauth2Error("invalid_client");
  static invalid_grant: Oauth2Error = new Oauth2Error("invalid_grant");
  static unauthorized_client: Oauth2Error = new Oauth2Error(
    "unauthorized_client"
  );
  static unsupported_grant_type: Oauth2Error = new Oauth2Error(
    "unsupported_grant_type"
  );

  public error: string;

  private constructor(error: string) {
    this.error = error;
  }
}

export interface Server {
  application: any; // eslint-disable-line
  start(options?: Partial<ServerOptions>): Promise<http.Server>;
}

export const createServer = (
  router: Router,
  logger: Logger,
  tokenRequestHandle: TokenRequestHandle,
  options: Partial<ServerOptions> = {}
): Server => {
  const pino = Pino({
    logger,
    useLevel: "debug",
    genReqId: () => uuid.v4().split("-")[0],
    quietReqLogger: true,
    autoLogging: {
      ignore: (req) => req.method === "OPTIONS",
    },
  });
  const app = express();

  app.use(pino);

  // eslint-disable-next-line @typescript-eslint/no-misused-promises
  app.engine("handlebars", engine());
  app.set("view engine", "handlebars");
  const viewsDir = path.join(__dirname, "..", "./views");
  app.set("views", viewsDir);

  app.get("/", (req, res) => {
    res.render("home");
  });

  app.use(
    cors({
      origin: "*",
    })
  );

  const publicDir = path.join(__dirname, "..", "./public");
  app.use(express.static(publicDir));

  app.use(express.json({ type: "application/x-amz-json-1.1" }));
  app.use(express.urlencoded({ extended: true }));

  app.get("/", (req, res) => {
    res.render("home");
  });
  app.post("/login", (req, res) => {
    res.status(200).json({ ok: true });
  });

  app.get("/:userPoolId/.well-known/jwks.json", (req, res) => {
    res.status(200).json({
      keys: [PublicKey.jwk],
    });
  });

  app.get("/:userPoolId/.well-known/openid-configuration", (req, res) => {
    res.status(200).json({
      id_token_signing_alg_values_supported: ["RS256"],
      jwks_uri: `http://localhost:9229/${req.params.userPoolId}/.well-known/jwks.json`,
      issuer: `http://localhost:9229/${req.params.userPoolId}`,
    });
  });

  app.get("/health", (req, res) => {
    res.status(200).json({ ok: true });
  });

  app.post("/oauth2/token/:domain", (req, res) => {
    /*tokenRequestHandle.tokenRequestHandle({ logger: req.log }, req.params.domain, req.body)
      .then(token => {
        res.status(200).json(token);
      });*/
    res.status(200).json({ ok: true });
  });

  app.post("/", (req, res) => {
    const xAmzTarget = req.headers["x-amz-target"];

    if (!xAmzTarget) {
      res.status(400).json({ message: "Missing x-amz-target header" });
      return;
    } else if (xAmzTarget instanceof Array) {
      res.status(400).json({ message: "Too many x-amz-target headers" });
      return;
    }

    const [, target] = xAmzTarget.split(".");
    if (!target) {
      res.status(400).json({ message: "Invalid x-amz-target header" });
      return;
    }

    const route = router(target);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const replacer: (this: any, key: string, value: any) => any = function (
      key,
      value
    ) {
      if (this[key] instanceof Date) {
        return Math.floor(this[key].getTime() / 1000);
      }
      return value;
    };

    route({ logger: req.log }, req.body).then(
      (output) =>
        res.status(200).type("json").send(JSON.stringify(output, replacer)),
      (ex) => {
        if (ex instanceof UnsupportedError) {
          if (options.development) {
            req.log.info("======");
            req.log.info("");
            req.log.info("Unsupported target");
            req.log.info("");
            req.log.info(`x-amz-target: ${xAmzTarget}`);
            req.log.info("Body:");
            req.log.info(JSON.stringify(req.body, undefined, 2));
            req.log.info("");
            req.log.info("======");
          }

          req.log.error(`Cognito Local unsupported feature: ${ex.message}`);
          res.status(500).json({
            __type: "CognitoLocal#Unsupported",
            message: `Cognito Local unsupported feature: ${ex.message}`,
          });
          return;
        } else if (ex instanceof CognitoError) {
          req.log.warn(ex, `Error handling target: ${target}`);
          res.status(400).json({
            __type: ex.code,
            message: ex.message,
          });
          return;
        } else {
          req.log.error(ex, `Error handling target: ${target}`);
          res.status(500).json(ex);
          return;
        }
      }
    );
  });

  return {
    application: app,
    start(startOptions) {
      const actualOptions: ServerOptions = {
        port: options?.port ?? 9229,
        hostname: options?.hostname ?? "localhost",
        development: options?.development ?? false,
        ...options,
        ...startOptions,
      };

      return new Promise((resolve, reject) => {
        const httpServer = app.listen(
          actualOptions.port,
          actualOptions.hostname,
          () => resolve(httpServer)
        );
        httpServer.on("error", reject);
      });
    },
  };
};
