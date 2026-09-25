import { basename, extname } from 'node:path';

import { derive } from '../../src/authzgen/derive';
import { loadSpec } from '../../src/authzgen/index';

/** Each argument is `<service>=<path>`, or a path whose filename names the service. */
const nameAndPath = (arg: string): [string, string] => {
  const at = arg.indexOf('=');
  if (at === -1) return [basename(arg, extname(arg)), arg];
  return [arg.slice(0, at), arg.slice(at + 1)];
};

async function main(): Promise<void> {
  for (const arg of process.argv.slice(2)) {
    const [service, rel] = nameAndPath(arg);
    try {
      const bundle = derive(await loadSpec(rel), service);
      console.log(`${rel}: OK service=${service} resourceTypes=[${bundle.resourceTypes}]`);
    } catch (e) {
      console.log(`${rel}: ${(e as Error).message}`);
    }
  }
}
void main();
