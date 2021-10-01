import { Algorithm } from 'jsonwebtoken';

export abstract class SigningKeyRepository {
  public abstract getAlgorithm(): Algorithm;
  public abstract getCurrentSigningKey(): Buffer;
  public abstract getCurrentVerificationKey(): Buffer;
}
