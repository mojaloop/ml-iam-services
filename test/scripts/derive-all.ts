import { derive } from '../../src/authzgen/derive';
import { loadSpec } from '../../src/authzgen/index';

async function main(): Promise<void> {
  for (const rel of process.argv.slice(2)) {
    try {
      const bundle = derive(await loadSpec(rel));
      console.log(`${rel}: OK resourceTypes=[${bundle.resourceTypes}]`);
    } catch (e) {
      console.log(`${rel}: ${(e as Error).message}`);
    }
  }
}
void main();
