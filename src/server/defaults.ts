import * as AWS from "aws-sdk";
import pino from "pino";
import {
  DateClock,
  LambdaService,
  MessagesService,
  TriggersService,
} from "../services";
import { CognitoServiceFactoryImpl } from "../services/cognitoService";
import { InMemoryCache } from "../services/dataStore/cache";
import { StormDBDataStoreFactory } from "../services/dataStore/stormDb";
import { ConsoleMessageSender } from "../services/messageDelivery/consoleMessageSender";
import { MessageDeliveryService } from "../services/messageDelivery/messageDelivery";
import { otp } from "../services/otp";
import { JwtTokenGenerator } from "../services/tokenGenerator";
import { UserPoolServiceFactoryImpl } from "../services/userPoolService";
import { Router } from "./Router";
import { loadConfig } from "./config";
import { createServer, Server } from "./server";
import { CryptoService } from "../services/crypto";
import { TokenRequestHandle } from "../targets/oauth2/tokenTarget";

export const createDefaultServer = async (
  logger: pino.Logger
): Promise<Server> => {
  const configDirectory = ".cognito";
  const dataDirectory = `${configDirectory}/db`;
  const ctx = {
    logger,
  };

  const config = await loadConfig(
    ctx,
    // the config gets a separate factory because it's stored in a different directory
    new StormDBDataStoreFactory(configDirectory, new InMemoryCache())
  );

  logger.debug({ config }, "Loaded config");

  const clock = new DateClock();

  const dataStoreFactory = new StormDBDataStoreFactory(
    dataDirectory,
    new InMemoryCache()
  );

  const cognitoServiceFactory = new CognitoServiceFactoryImpl(
    dataDirectory,
    clock,
    dataStoreFactory,
    new UserPoolServiceFactoryImpl(clock, dataStoreFactory)
  );
  const cognitoClient = await cognitoServiceFactory.create(
    ctx,
    config.UserPoolDefaults
  );
  const triggers = new TriggersService(
    clock,
    cognitoClient,
    new LambdaService(
      config.TriggerFunctions,
      new AWS.Lambda(config.LambdaClient)
    ),
    new CryptoService(config.KMSConfig)
  );

  const messages = new MessagesService(
    triggers,
    new MessageDeliveryService(new ConsoleMessageSender())
  );
  const services = {
    clock,
    cognito: cognitoClient,
    config,
    messages: messages,
    otp,
    tokenGenerator: new JwtTokenGenerator(clock, triggers, config.TokenConfig),
    triggers,
  };
  return createServer(
    cognitoClient,
    Router(services),
    logger,
    new TokenRequestHandle(services),
    {
      development: !!process.env.COGNITO_LOCAL_DEVMODE,
    }
  );
};
