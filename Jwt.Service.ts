import { sign, verify } from 'jsonwebtoken';
import { SigningKeyRepository } from './SigningKey.Repository';
import { Claims } from './Claims';

export class JwtService {
  constructor(private readonly repository: SigningKeyRepository) {}

  public generate(claims: Claims): string {
    return sign(claims, this.repository.getCurrentSigningKey(), {
      algorithm: this.repository.getAlgorithm(),
      subject: claims.user_id,
      expiresIn: '1 hour',
    });
  }

  public verify(token: string): Claims {
    const result = verify(token, this.repository.getCurrentVerificationKey(), {
      algorithms: [this.repository.getAlgorithm()],
    });

    if (typeof result === 'string') {
      throw new Error(`Unsupported JWT format`);
    }

    return {
      user_id: result.user_id,
      email: result.email,
    };
  }
}
