#!/usr/bin/env node

import { Command } from 'commander';
import { config } from 'dotenv';

import { start as startCapabilities } from './capabilities/server';
import { start as startDecision } from './decision/server';
import { start as startProvisioning } from './iam/server';
import { start as startKetoBatchAuth } from './keto-batch-auth/server';
import { start as startKratosRoleWebhook } from './kratos-role-webhook/server';

config();

const program = new Command();

program.name('ory-services').description('Mojaloop Ory IAM Services').version('0.1.0');

program
  .command('keto-batch-auth')
  .description('Start the Keto batch authorization proxy')
  .action(startKetoBatchAuth);

program
  .command('kratos-role-webhook')
  .description('Start the Kratos role injection webhook')
  .action(startKratosRoleWebhook);

program
  .command('capabilities')
  .description('Start the capabilities service')
  .action(startCapabilities);

program
  .command('decide')
  .description('Start the decision endpoint the gateway asks for every request')
  .action(startDecision);

program
  .command('provisioning')
  .description("Apply the deployment's roles, then serve the IAM the role UI and services call")
  .requiredOption('-r, --roles <path>', 'path to the role document')
  .option(
    '-c, --catalog <path...>',
    'composed catalogs to read, when it composes no namespace of its own',
  )
  .option('--migrations <path>', 'where the grants of a renamed or retired permission go')
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
    'namespace the composed rules and catalog are published into',
    process.env.POD_NAMESPACE,
  )
  .option('--resource-names <path>', "the deployment's names for one thing across services")
  .option('--publish-as <name>', 'ConfigMap the composed rules and catalog are published as')
  .option('--webhook-cert-dir <dir>', 'tls.crt and tls.key to answer AuthzDocument admission with')
  .action(startProvisioning);

program.parse();
