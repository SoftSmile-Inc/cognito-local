import { CognitoService, DateClock } from "../../services";
import { Context } from "../../services/context";

type GrantType = "authorization_code" | "refresh_token" | "client_credentials";

interface TokenRequest {
  grant_type: GrantType;
  client_id: string;
  client_secret: string;
  scope: string;
  redirect_uri: string;
  refresh_token: string;
  code: string;
}

interface TokenResponse {
  access_token: string;
  id_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export class TokenRequestHandle {
  clock: DateClock;
  cognitoService: CognitoService;

  constructor(clock: DateClock, cognitoService: CognitoService) {
    this.clock = clock;
    this.cognitoService = cognitoService;
  }

  public tokenRequestHandle = (
    ctx: Context,
    domain: string,
    req: TokenRequest
  ): TokenResponse => {
    //const userPool = await this.cognitoService.getUserPool(ctx, req.UserPoolId);
    //const existingUser = await userPool.getUserByUsername(ctx, req.Username);
    const res: TokenResponse = {
      access_token: "",
      id_token: "",
      refresh_token: "",
      token_type: "",
      expires_in: 0,
    };
    return res;
  };
}
