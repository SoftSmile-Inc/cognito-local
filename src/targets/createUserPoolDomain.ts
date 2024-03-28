import {
  CreateUserPoolDomainRequest,
  CreateUserPoolDomainResponse,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import { InvalidParameterError, PoolNotFoundError } from "../errors";
import { Services } from "../services";
import { Target } from "./Target";

export type CreateUserPoolDomainTarget = Target<
  CreateUserPoolDomainRequest,
  CreateUserPoolDomainResponse
>;

type CreateUserPoolDomainServices = Pick<Services, "cognito">;

export const CreateUserPoolDomain =
  ({ cognito }: CreateUserPoolDomainServices): CreateUserPoolDomainTarget =>
  async (ctx, req) => {
    if (!req.Domain) throw new InvalidParameterError("Domain is required");
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    if (!userPool) throw new PoolNotFoundError("User Pool not found");
    await userPool.savePoolDomain(ctx, {
      Domain: req.Domain,
      UserPoolId: req.UserPoolId,
    });
    if (!userPool.options.Domain) {
      const newOptions = userPool.options;
      newOptions.Domain = req.Domain;
      // if this is first domain for the user pool, save it there
      userPool.options.Domain = req.Domain;
      await userPool.updateOptions(ctx, newOptions);
    }

    return {
      CloudFrontDomain: `https://localhost:9000/{req.Domain}`,
    };
  };
