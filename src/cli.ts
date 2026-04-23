#!/usr/bin/env node

import { Command } from 'commander';
import { config } from 'dotenv';

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

program.parse();
