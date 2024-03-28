import { Services } from "../../services";
import { Context } from "../../services/context";
import { refreshTokenAuthFlow, userPasswordAuthFlow } from "../initiateAuth";
import { Tokens } from "../../services/tokenGenerator";
import { AuthParametersType } from "aws-sdk/clients/cognitoidentityserviceprovider";

export interface TokenEndpointRequest {
  grant_type: "authorization_code" | "refresh_token" | "client_credentials";
  client_id?: string;
  client_secret?: string;
  scope?: string;
  redirect_uri?: string;
  refresh_token?: string;
  code?: string;
  code_verifier?: string;
}

export interface UserCredentials {
  email: string;
  password: string;
}

export interface TokenResponse {
  access_token: string;
  id_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

type TokenRequestHandleServices = Pick<
  Services,
  | "cognito"
  | "messages"
  | "otp"
  | "tokenGenerator"
  | "triggers"
  | "clock"
  | "tokenGenerator"
>;

export class TokenRequestHandle {
  constructor(private services: TokenRequestHandleServices) {}

  public tokenCodeHandle = async (
    ctx: Context,
    domain: string,
    clientId: string,
    email: string
  ): Promise<TokenResponse> => {
    if (!clientId) throw new Error("Client ID is required");
    const foundDomain = await this.services.cognito.getDomain(ctx, domain);
    if (!foundDomain) throw new Error("Domain not found");
    const userPool = await this.services.cognito.getUserPool(
      ctx,
      foundDomain.UserPoolId
    );
    const user = await userPool.getUserByUsername(ctx, email);
    if (!user) throw new Error("User not found");
    const userPoolClient = await this.services.cognito.getAppClient(
      ctx,
      clientId
    );
    if (!userPoolClient) {
      throw new Error("Client not found");
    }

    const userGroups = await userPool.listUserGroupMembership(ctx, user);
    const tokens = await this.services.tokenGenerator.generate(
      ctx,
      user,
      userGroups,
      userPoolClient,
      // The docs for the pre-token generation trigger only say that the ClientMetadata is passed as part of the
      // AdminRespondToAuthChallenge and RespondToAuthChallenge triggers.
      //
      // source: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-token-generation.html
      undefined,
      "Authentication"
    );

    await userPool.storeRefreshToken(ctx, tokens.RefreshToken, user);

    return this.createResponse(tokens);
  };

  private createResponse = (tokens: Tokens): TokenResponse => {
    return {
      access_token: tokens.AccessToken || "",
      id_token: tokens.IdToken || "",
      refresh_token: tokens.RefreshToken || "",
      token_type: "Bearer",
      expires_in: 3600,
    };
  };

  public tokenLoginPasswordHandle = async (
    ctx: Context,
    domain: string,
    auth: UserCredentials,
    req: TokenEndpointRequest
  ): Promise<TokenResponse> => {
    if (!req.client_id) throw new Error("Client ID is required");
    const foundDomain = await this.services.cognito.getDomain(ctx, domain);
    if (!foundDomain) throw new Error("Domain not found");
    const userPool = await this.services.cognito.getUserPool(
      ctx,
      foundDomain.UserPoolId
    );

    const user = await userPool.getUserByUsername(ctx, auth.email);
    if (!user) throw new Error("User not found");
    const userPoolClient = await this.services.cognito.getAppClient(
      ctx,
      req.client_id
    );
    if (!userPoolClient) {
      throw new Error("Client not found");
    }

    const authParameters: AuthParametersType = {};
    authParameters.USERNAME = auth.email;
    authParameters.PASSWORD = auth.password;
    const result = await userPasswordAuthFlow(
      ctx,
      {
        AuthFlow: "USER_PASSWORD_AUTH",
        ClientId: req.client_id,
        AuthParameters: authParameters,
      },
      userPool,
      userPoolClient,
      {
        cognito: this.services.cognito,
        messages: this.services.messages,
        otp: this.services.otp,
        tokenGenerator: this.services.tokenGenerator,
        triggers: this.services.triggers,
      }
    );
    if (!result.AuthenticationResult) throw new Error("Authentication failed");
    const tokens = result.AuthenticationResult as Tokens;

    return this.createResponse(tokens);
  };

  public tokenRefreshHandle = async (
    ctx: Context,
    domain: string,
    refreshToken: string,
    request: TokenEndpointRequest
  ): Promise<TokenResponse> => {
    if (!request.client_id) throw new Error("Client ID is required");
    const foundDomain = await this.services.cognito.getDomain(ctx, domain);
    if (!foundDomain) throw new Error("Domain not found");
    const userPool = await this.services.cognito.getUserPool(
      ctx,
      foundDomain.UserPoolId
    );
    const userPoolClient = await this.services.cognito.getAppClient(
      ctx,
      request.client_id
    );
    if (!userPoolClient) {
      throw new Error("Client not found");
    }

    const authParameters: AuthParametersType = {};
    authParameters.REFRESH_TOKEN = refreshToken;
    const result = await refreshTokenAuthFlow(
      ctx,
      {
        AuthFlow: "REFRESH_TOKEN",
        ClientId: request.client_id,
        AuthParameters: authParameters,
      },
      userPool,
      userPoolClient,
      {
        cognito: this.services.cognito,
        messages: this.services.messages,
        otp: this.services.otp,
        tokenGenerator: this.services.tokenGenerator,
        triggers: this.services.triggers,
      }
    );
    if (!result.AuthenticationResult) throw new Error("Authentication failed");
    const tokens = result.AuthenticationResult as Tokens;
    return this.createResponse(tokens);
  };
}
