import { Algorithm } from 'jsonwebtoken';
import { SigningKeyRepository } from './SigningKey.Repository';
import { JwtConfig } from './JwtConfig';
import { join } from 'path';
import { readFileSync } from 'fs';

export class RS256SigningKeyRepository implements SigningKeyRepository {
  private readonly keypairPrefix = 'jwt-signing-key.rs256';

  private readonly privateKey: Buffer;
  private readonly publicKey: Buffer;

  constructor(private readonly config: JwtConfig) {
    this.privateKey = this.readKey(`.pem`);
    this.publicKey = this.readKey(`.public.pem`);
  }

  private readKey(extension: string) {
    const path = join(
      this.config.keysDirectory,
      `${this.keypairPrefix}${extension}`,
    );

    try {
      return readFileSync(path);
    } catch (e) {
      throw new Error(`Cannot read RS256 key at ${path}: ${e.message}`);
    }
  }

  getAlgorithm(): Algorithm {
    return 'RS256';
  }

  getCurrentSigningKey(): Buffer {
    return this.privateKey;
  }

  getCurrentVerificationKey(): Buffer {
    return this.publicKey;
  }
}
