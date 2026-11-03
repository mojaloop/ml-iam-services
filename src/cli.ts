#!/usr/bin/env node

import { Command } from 'commander';
import { config } from 'dotenv';

import { start as startApi } from './api/start';
import { start as startController } from './controller/server';
import { start as startDecision } from './decision/server';

config({ quiet: true });

const program = new Command();

program.name('ml-iam-services').description('Mojaloop IAM').version('0.1.0');

program
  .command('decide')
  .description('Start the decision endpoint the gateway asks for every request')
  .action(startDecision);

program
  .command('controller')
  .description(
    "Compose the deployment's routes and documents, apply its roles and separation rules, answer admission, and write every assignment",
  )
  .option(
    '--admin-email <email>',
    'identity to create and add to the admin role',
    process.env.IAM_ADMIN_EMAIL,
  )
  .option(
    '--admin-password <password>',
    'password for that identity, invited by email to set one when omitted',
    process.env.IAM_ADMIN_PASSWORD,
  )
  .option('--admin-role <role>', 'role that identity joins', process.env.IAM_HUB_ADMIN_ROLE)
  .option('--kratos-admin-url <url>', 'Kratos admin API', process.env.KRATOS_ADMIN_URL)
  .option(
    '--kratos-public-url <url>',
    'Kratos public API, where the invitation flow starts',
    process.env.KRATOS_PUBLIC_URL,
  )
  .option(
    '--namespace <namespace>',
    'namespace the composition is published into',
    process.env.POD_NAMESPACE,
  )
  .option('--publish-as <name>', 'ConfigMap the composed rules and model are published as')
  .option(
    '--announce-as <name>',
    "ConfigMap the composition's ETag is announced in, for the API process",
  )
  .option(
    '--history-as <name>',
    'ConfigMap every permission ever composed is kept in, to tell a renamed one from a removed one',
  )
  .option(
    '--serves-as <prefix>',
    "the prefix the IAM's own route gives its public API, whose roles and permissions it records",
  )
  .option('--webhook-cert-dir <dir>', 'tls.crt and tls.key to answer admission with')
  .option(
    '--lease <name>',
    'Lease the replicas elect their one writer through; without one, this process writes alone',
  )
  .action(startController);

program
  .command('api')
  .description(
    "Serve the public API through the gateway and the provisioning authority's internal API",
  )
  .option('--controller-url <url>', "the controller's API", process.env.CONTROLLER_URL)
  .option(
    '--namespace <namespace>',
    'namespace roles composed here are written into',
    process.env.POD_NAMESPACE,
  )
  .option('--announced-in <name>', "ConfigMap the controller announces the composition's ETag in")
  .option('--kratos-admin-url <url>', 'Kratos admin API', process.env.KRATOS_ADMIN_URL)
  .option(
    '--kratos-public-url <url>',
    'Kratos public API, where the invitation flow starts',
    process.env.KRATOS_PUBLIC_URL,
  )
  .option(
    '--hydra-admin-url <url>',
    'Hydra admin API, which keeps machine clients',
    process.env.HYDRA_ADMIN_URL,
  )
  .action(startApi);

program.parse();
