import cors from "cors";
import express from "express";
import * as http from "http";
import type { Logger } from "pino";
import * as uuid from "uuid";
import { CognitoError, PoolNotFoundError, UnsupportedError } from "../errors";
import { Router } from "./Router";
import PublicKey from "../keys/cognitoLocal.public.json";
import Pino from "pino-http";
import path from "path";
import {
  TokenRequestHandle,
  UserCredentials,
  TokenEndpointRequest,
} from "../targets/oauth2/tokenTarget";
import { CognitoService } from "../services";
import { Context } from "../services/context";
import * as crypto from "crypto";
import cookieParser from "cookie-parser";
import { Request } from "express";

export interface ServerOptions {
  port: number;
  hostname: string;
  development: boolean;
}

interface AuthorizationEndpointRequest {
  response_type: "code" | "token";
  client_id: string;
  redirect_uri: string;
  state?: string;
  code_challenge_method: "S256";
  code_challenge: string;
}

interface OpenIdConfiguration {
  authorization_endpoint: string;
  end_session_endpoint: string;
  id_token_signing_alg_values_supported: string[];
  issuer: string;
  jwks_uri: string;
  response_types_supported: string[];
  revocation_endpoint: string;
  scopes_supported: string[];
  subject_types_supported: string[];
  token_endpoint: string;
  token_endpoint_auth_methods_supported: string[];
  userinfo_endpoint: string;
}

class OpenIdConfigurationImpl implements OpenIdConfiguration {
  authorization_endpoint: string;
  end_session_endpoint: string;
  id_token_signing_alg_values_supported: string[];
  issuer: string;
  jwks_uri: string;
  response_types_supported: string[];
  revocation_endpoint: string;
  scopes_supported: string[];
  subject_types_supported: string[];
  token_endpoint: string;
  token_endpoint_auth_methods_supported: string[];
  userinfo_endpoint: string;

  constructor(
    host: string,
    isHttps: boolean,
    userPoolId: string,
    domainName: string
  ) {
    const hostWithProtocol = isHttps ? `https://${host}` : `http://${host}`;
    this.authorization_endpoint = `${hostWithProtocol}/${domainName}/oauth2/authorize`;
    this.end_session_endpoint = `${hostWithProtocol}/${domainName}/logout`;
    this.id_token_signing_alg_values_supported = ["RS256"];
    this.issuer = `${hostWithProtocol}/${userPoolId}`;
    this.jwks_uri = `${hostWithProtocol}/${userPoolId}/.well-known/jwks.json`;
    this.response_types_supported = ["code", "token"];
    this.revocation_endpoint = `${hostWithProtocol}/${domainName}/oauth2/revoke`;
    this.scopes_supported = ["openid", "email", "phone", "profile"];
    this.subject_types_supported = ["public"];
    this.token_endpoint = `${hostWithProtocol}/${domainName}/oauth2/token`;
    this.token_endpoint_auth_methods_supported = [
      "client_secret_basic",
      "client_secret_post",
    ];
    this.userinfo_endpoint = `${hostWithProtocol}/${domainName}/oauth2/userinfo`;
  }
}

export interface Server {
  application: any; // eslint-disable-line
  start(options?: Partial<ServerOptions>): Promise<http.Server>;
}

const getDomainByUserPoolId = async (
  host: string,
  isHttps: boolean,
  ctx: Context,
  cognitoService: CognitoService,
  userPoolId: string
): Promise<OpenIdConfiguration> => {
  const userPool = await cognitoService.getUserPool(ctx, userPoolId);
  if (!userPool) throw new PoolNotFoundError("User Pool not found");
  const domain = userPool.options.Domain;
  if (!domain) throw new Error("The user pool does not have a domain");
  return new OpenIdConfigurationImpl(host, isHttps, userPoolId, domain);
};

interface LogoutQueryParams {
  client_id: string;
  logout_uri: string;
}

type LogoutAuthorizePathParams = { ["domain"]: string };
type LogoutAuthorizeRequest = Request<
  LogoutAuthorizePathParams,
  {},
  {},
  LogoutQueryParams
>;

type GetAuthorizePathParams = { ["domain"]: string };
type GetAuthorizeRequest = Request<
  GetAuthorizePathParams,
  {},
  {},
  AuthorizationEndpointRequest
>;

interface UserCredentialsWithRememberMe extends UserCredentials {
  remember_me: "on" | undefined;
}

type PostAuthorizePathParams = { ["domain"]: string };
type PostAuthorizePathRequest = Request<
  PostAuthorizePathParams,
  {},
  UserCredentialsWithRememberMe,
  AuthorizationEndpointRequest
>;

type PostTokenPathParams = { ["domain"]: string };
type PostTokenRequest = Request<
  PostTokenPathParams,
  {},
  TokenEndpointRequest,
  {}
>;

const getAuthorizeDomainCookieName = (domain: string) => {
  return `${domain}-authorizedAs`;
};

const getHostWithProtocol = (req: Request<{}, {}, {}, {}>) => {
  if (!req.headers.host) {
    throw new Error("Missing host header");
  }
  return req.secure
    ? `https://${req.headers.host}`
    : `http://${req.headers.host}`;
};

export const createServer = (
  cognito: CognitoService,
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
  app.use(cookieParser());

  app.use(pino);

  // I dot't think it's the right way, but without it docker doesn't work
  app.engine("pug", require("pug").__express);
  app.set("view engine", "pug");
  const viewsDir = path.join(__dirname, "..", "./views");
  app.set("views", viewsDir);

  app.use(
    cors({
      origin: "*",
    })
  );

  const publicDir = path.join(__dirname, "..", "./public");
  app.use(express.static(publicDir));

  app.use(express.json({ type: "application/x-amz-json-1.1" }));
  app.use(express.urlencoded({ extended: true }));

  app.get("/:domain/logout", (req: LogoutAuthorizeRequest, res) => {
    if (!req.params.domain) {
      res.status(400).json({ message: "Missing domain" });
      return;
    }
    const cookieName = getAuthorizeDomainCookieName(req.params.domain);
    res.clearCookie(cookieName);
    res.redirect(req.query.logout_uri);
  });

  app.get("/:domain/oauth2/authorize", (req: GetAuthorizeRequest, res) => {
    if (!req.params.domain) {
      res.status(400).json({ message: "Missing domain" });
      return;
    }
    const authorizedAs: string | undefined =
      req.cookies[getAuthorizeDomainCookieName(req.params.domain)];
    if (authorizedAs) {
      const encodedMail = Buffer.from(authorizedAs).toString("base64");
      const encodedCode = Buffer.from(
        `${encodedMail}|${req.query.code_challenge}`
      )
        .toString("base64")
        .replace(/=+$/, "");
      res.redirect(
        `${req.query.redirect_uri}?code=${encodedCode}&state=${req.query.state}`
      );
      return;
    }
    if (!req.query.client_id) {
      res.status(400).json({ message: "Missing client_id" });
      return;
    }
    if (!req.query.response_type) {
      res.status(400).json({ message: "Missing response_type" });
      return;
    }
    if (!req.query.redirect_uri) {
      res.status(400).json({ message: "Missing redirect_uri" });
      return;
    }
    if (req.query.response_type !== "code") {
      res.status(400).json({ message: "Only code response_type is supported" });
      return;
    }
    const body: AuthorizationEndpointRequest = {
      client_id: req.query.client_id,
      redirect_uri: req.query.redirect_uri,
      response_type: req.query.response_type,
      state: req.query.state,
      code_challenge: req.query.code_challenge,
      code_challenge_method: "S256",
    };
    res.render("login", { domain: req.params.domain, body: body });
  });

  app.post(
    "/:domain/oauth2/authorize",
    (req: PostAuthorizePathRequest, res) => {
      if (!req.query.client_id) {
        res.status(400).json({ message: "Missing client_id" });
        return;
      }
      if (!req.query.response_type) {
        res.status(400).json({ message: "Missing response_type" });
        return;
      }
      if (!req.query.redirect_uri) {
        res.status(400).json({ message: "Missing redirect_uri" });
        return;
      }
      const domain = req.params.domain;
      if (!domain) {
        res.status(400).json({ message: "Missing domain" });
        return;
      }
      if (req.query.response_type !== "code") {
        res
          .status(400)
          .json({ message: "Only 'code' response_type is supported" });
        return;
      }
      tokenRequestHandle
        .tokenLoginPasswordHandle(
          { logger, hostWithProtocol: getHostWithProtocol(req) },
          domain,
          req.body,
          {
            client_id: req.query.client_id,
            redirect_uri: req.query.redirect_uri,
            client_secret: "",
            code: "",
            grant_type: "client_credentials",
            refresh_token: "",
            scope: "",
          }
        )
        .then(
          () => {
            const encodedMail = Buffer.from(req.body.email).toString("base64");
            const encodedCode = Buffer.from(
              `${encodedMail}|${req.query.code_challenge}`
            )
              .toString("base64")
              .replace(/=+$/, "");
            if (req.body.remember_me) {
              const cookieName = getAuthorizeDomainCookieName(domain);
              res.cookie(cookieName, req.body.email, { maxAge: 3600 * 1000 });
            }
            res.redirect(
              `${req.query.redirect_uri}?code=${encodedCode}&state=${req.query.state}`
            );
          },
          (err) => {
            res.status(500).json({ err: `Internal server error: ${err}` });
          }
        );
    }
  );

  app.get("/:userPoolId/.well-known/jwks.json", (req, res) => {
    res.status(200).json({
      keys: [PublicKey.jwk],
    });
  });

  app.get("/:userPoolId/.well-known/openid-configuration", (req, res) => {
    if (!req.headers.host) {
      res.status(400).json({ message: "Missing host header" });
      return;
    }
    getDomainByUserPoolId(
      req.headers.host,
      req.secure,
      { logger: req.log, hostWithProtocol: getHostWithProtocol(req) },
      cognito,
      req.params.userPoolId
    ).then(
      (val) => {
        res.status(200).json(val);
      },
      (err) => {
        res.status(500).json(err);
      }
    );
  });

  app.get("/health", (req, res) => {
    res.status(200).json({ ok: true });
  });

  app.post("/:domain/oauth2/token", (req: PostTokenRequest, res) => {
    if (req.body.grant_type === "authorization_code") {
      if (!req.body.code) {
        res.status(400).json({ message: "Missing code in request" });
        return;
      }
      const code = Buffer.from(req.body.code, "base64");
      const [encodedMail, codeChallenge] = code.toString().split("|");
      const mail = Buffer.from(encodedMail, "base64").toString();
      const codeVerifier: string | undefined = req.body.code_verifier;
      if (!codeVerifier) {
        res.status(400).json({ message: "Missing code verifier" });
        return;
      }
      const calculatedCodeChallenge = crypto
        .createHash("sha256")
        .update(codeVerifier)
        .digest("base64")
        // TrimEnd("=")
        .replace(/=+$/, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
      if (calculatedCodeChallenge !== codeChallenge) {
        res.status(400).json({ message: "Code challenge different" });
        return;
      }
      if (!req.body.client_id) {
        res.status(400).json({ message: "Missing client_id" });
        return;
      }
      tokenRequestHandle
        .tokenCodeHandle(
          { logger: req.log, hostWithProtocol: getHostWithProtocol(req) },
          req.params.domain,
          req.body.client_id,
          mail
        )
        .then(
          (token) => res.status(200).json(token),
          (err) =>
            res.status(500).json({ err: `Internal server error: ${err}` })
        );
    } else if (req.body.grant_type === "client_credentials") {
      const authHeader = req.headers["authorization"];
      if (!authHeader) {
        res.status(400).json({ message: "Missing Authorization header" });
        return;
      }
      const authEncoded = authHeader.replace("Basic ", "");
      const authDecoded = Buffer.from(authEncoded, "base64").toString();
      const indexOfSplitCharacter = authDecoded.indexOf(":");
      const username = authDecoded.substring(0, indexOfSplitCharacter);
      const password = authDecoded.substring(indexOfSplitCharacter + 1);

      tokenRequestHandle
        .tokenLoginPasswordHandle(
          { logger: req.log, hostWithProtocol: getHostWithProtocol(req) },
          req.params.domain,
          {
            email: username,
            password: password,
          },
          {
            ...req.body,
          }
        )
        .then(
          (val) => {
            res.status(200).json(val);
          },
          (err) =>
            res.status(500).json({ err: `Internal server error: ${err}` })
        );
    } else if (req.body.grant_type === "refresh_token") {
      const authHeader = req.headers["authorization"];
      if (!authHeader) {
        res.status(400).json({ message: "Missing Authorization header" });
        return;
      }
      const refreshToken = authHeader.replace("Basic ", "");
      tokenRequestHandle
        .tokenRefreshHandle(
          { logger: req.log, hostWithProtocol: getHostWithProtocol(req) },
          req.params.domain,
          refreshToken,
          req.body
        )
        .then(
          (token) => res.status(200).json(token),
          (err) =>
            res.status(500).json({ err: `Internal server error: ${err}` })
        );
    } else {
      res.status(400).json({ message: "Unsupported grant type" });
    }
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

    route(
      { logger: req.log, hostWithProtocol: getHostWithProtocol(req) },
      req.body
    ).then(
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
